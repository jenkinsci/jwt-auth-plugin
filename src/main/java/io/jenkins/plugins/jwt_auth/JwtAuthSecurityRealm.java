/*
 * The MIT License
 *
 * Copyright (c) 2021 Swisscom (Schweiz) AG, Dario Nuevo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.jenkins.plugins.jwt_auth;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.jwt_auth.util.JwtVerifierPicker;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author Kohsuke Kawaguchi
 */
public class JwtAuthSecurityRealm extends SecurityRealm {

	private static final Logger LOGGER = Logger.getLogger(JwtAuthSecurityRealm.class.getName());

	/**
	 * apparently we need to create an instance here so the auth0 has no runtime problems(?)
	 */
	private static final ObjectMapper mapper = new ObjectMapper();

	/**
	 * map from username to groups
	 */
	public transient Hashtable<String, List<GrantedAuthority>> userToGroupsCache;

	/**
	 * jwk provider
	 */
	public transient JwkProvider jwkProvider;

	private final String headerName;
	private final String userClaimName;
	private final String groupsClaimName;
	private final String groupsClaimSeparator;
	private final String jwksUrl;
	private final int leewaySeconds;
	private final boolean allowVerificationFailures;

	@DataBoundConstructor
	public JwtAuthSecurityRealm(
			String headerName,
			String userClaimName,
			String groupsClaimName,
			String groupsClaimSeparator,
			String jwksUrl,
			int leewaySeconds,
			boolean allowVerificationFailures
	) throws MalformedURLException {
		super();
		this.headerName = Util.fixEmptyAndTrim(headerName);
		this.userClaimName = Util.fixEmptyAndTrim(userClaimName);
		this.groupsClaimName = Util.fixEmptyAndTrim(groupsClaimName);
		this.groupsClaimSeparator = Util.fixEmpty(groupsClaimSeparator);
		this.jwksUrl = Util.fixEmpty(jwksUrl);
		this.leewaySeconds = leewaySeconds;
		this.allowVerificationFailures = allowVerificationFailures;
	}

	/**
	 * this does not actually do anything as we only use the filter based auth
	 *
	 * @return default component
	 */
	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents();
	}

	@Override
	public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
		if (!userToGroupsCache.containsKey(username)) {
			throw new UsernameNotFoundException(username + " could not be found");
		}

		return new JwtAuthUserDetails(
				username,
				userToGroupsCache.get(username)
		);
	}

	@Override
	public boolean allowsSignup() {
		return false;
	}

	@Override
	public boolean canLogOut() {
		return false;
	}

	/**
	 * Our filter
	 */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		Filter filter = new Filter() {

			@Override
			public void init(FilterConfig filterConfig) throws ServletException {
			}

			@Override
			public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
					FilterChain filterChain) throws IOException, ServletException {

				SecurityContextHolder.getContext().setAuthentication(
						getAuthFromToken(servletRequest)
				);

				filterChain.doFilter(servletRequest, servletResponse);
			}

			private Authentication getAuthFromToken(ServletRequest servletRequest) {
				if (!(servletRequest instanceof HttpServletRequest)) {
					return Jenkins.ANONYMOUS2;
				}

				HttpServletRequest request = (HttpServletRequest) servletRequest;
				String headerContent = request.getHeader(headerName);

				if (headerContent == null || headerContent.isEmpty()) {
					return Jenkins.ANONYMOUS2;
				}

				// strip bearer stuff from content if present
				headerContent = headerContent
						.replace("Bearer", "")
						.replace("bearer", "")
						.trim();

				try {

					// decode the token
					DecodedJWT jwt = JWT.decode(headerContent);

					// do we need to prepare for verification?
					if (jwksUrl != null && !jwksUrl.isEmpty() && jwkProvider == null) {
						jwkProvider = new GuavaCachedJwkProvider(
								new UrlJwkProvider(
										new URL(jwksUrl)
								)
						);
					}

					// do we need to verify?
					if (jwkProvider != null) {
						String keyId = jwt.getKeyId();
						Jwk jwk = jwkProvider.get(keyId);
						JWTVerifier verifier = JwtVerifierPicker.getVerifier(jwk, leewaySeconds);

						// verify it..
						try {
							verifier.verify(jwt);
						} catch (Throwable t) {
							if (!allowVerificationFailures) {
								throw t;
							} else {
								LOGGER.log(Level.SEVERE, "Error during JWT verification", t);
							}
						}
					}

					// get username
					String username = jwt.getClaim(userClaimName).asString();

					// get groups.. try as list first..
					List<String> groups;
					groups = jwt.getClaim(groupsClaimName).asList(String.class);
					if (groups == null && groupsClaimSeparator != null && !groupsClaimSeparator.isEmpty()) {
						// fall back and try to expose a string into a list
						String groupList = jwt.getClaim(groupsClaimName).asString();
						groups = Arrays.asList(StringUtils.splitPreserveAllTokens(groupList, groupsClaimSeparator));
					}

					if (groups == null) {
						LOGGER.log(
								Level.WARNING,
								"Unable to read groups from claim '" + groupsClaimName + "'. " +
										"Consider checking if it's a list or string and configure a correct separator."
						);
						groups = new ArrayList<>();
					}

					List<GrantedAuthority> grantedGroups = getGrantedGroups(groups);

					if (userToGroupsCache == null) {
						userToGroupsCache = new Hashtable<>();
					}

					// put it in our "cache"
					userToGroupsCache.put(username, grantedGroups);

					return new JwtAuthAuthenticationToken(username, grantedGroups);
				} catch (Throwable exception){
					LOGGER.log(Level.SEVERE, "Could not decode the JWT", exception);
					// will return anonymous again in the end
				}

				return Jenkins.ANONYMOUS2;
			}

			@Override
			public void destroy() {

			}
		};

		Filter defaultFilter = super.createFilter(filterConfig);
		return new ChainedServletFilter(defaultFilter, filter);
	}

	private List<GrantedAuthority> getGrantedGroups(List<String> groupNames) {
		List<GrantedAuthority> groups = new ArrayList<>();
		groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

		groupNames.forEach(group -> {
			groups.add(new SimpleGrantedAuthority(group));
		});

		return groups;
	}

	/**
	 * Descriptor for help and so on..
	 */
	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

		@Override
		public String getHelpFile() {
			return "/plugin/jwt-auth/help/help-security-realm.html";
		}

		@NonNull
		@Override
		public String getDisplayName() {
			return "JWT Header Authentication Plugin";
		}

		public String getDefaultHeaderName() {
			return "Authorization";
		}
		public String getDefaultUsernameClaimName() {
			return "email";
		}
		public String getDefaultGroupsClaimName() {
			return "groups";
		}

		public DescriptorImpl() {
			super();
		}

		public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
			super(clazz);
		}
	}

	@Override
	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();
	}

	/** getters **/
	public String getHeaderName() {
		return headerName;
	}

	public String getUserClaimName() {
		return userClaimName;
	}

	public String getGroupsClaimName() {
		return groupsClaimName;
	}

	public String getGroupsClaimSeparator() {
		return groupsClaimSeparator;
	}

	public String getJwksUrl() {
		return jwksUrl;
	}

	public int getLeewaySeconds() {
		return leewaySeconds;
	}

	public boolean isAllowVerificationFailures() {
		return allowVerificationFailures;
	}
}
