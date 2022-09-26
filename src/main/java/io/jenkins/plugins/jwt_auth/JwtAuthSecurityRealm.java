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

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;

import java.io.IOException;
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
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
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
	 * map from username to groups
	 */
	public transient Hashtable<String, List<GrantedAuthority>> userToGroupsCache;

	/**
	 * jwks resolver
	 */
	public transient HttpsJwksVerificationKeyResolver jwksResolver;

	private final String headerName;
	private final String userClaimName;
	private final String groupsClaimName;
	private final String groupsClaimSeparator;
	private final String acceptedIssuer;
	private final String acceptedAudience;
	private final String jwksUrl;
	private final int leewaySeconds;
	private final boolean allowVerificationFailures;
	private final String emailClaimName;
	private final String fullNameClaim;

	@DataBoundConstructor
	public JwtAuthSecurityRealm(
			String headerName,
			String userClaimName,
			String groupsClaimName,
			String groupsClaimSeparator,
			String acceptedIssuer,
			String acceptedAudience,
			String jwksUrl,
			int leewaySeconds,
			boolean allowVerificationFailures,
			String emailClaimName,
			String fullNameClaim
	) {
		super();
		this.headerName = Util.fixEmptyAndTrim(headerName);
		this.userClaimName = Util.fixEmptyAndTrim(userClaimName);
		this.groupsClaimName = Util.fixEmptyAndTrim(groupsClaimName);
		this.groupsClaimSeparator = Util.fixEmpty(groupsClaimSeparator);
		this.acceptedIssuer = Util.fixEmptyAndTrim(acceptedIssuer);
		this.acceptedAudience = Util.fixEmptyAndTrim(acceptedAudience);
		this.jwksUrl = Util.fixEmpty(jwksUrl);
		this.leewaySeconds = leewaySeconds;
		this.allowVerificationFailures = allowVerificationFailures;
		this.emailClaimName = emailClaimName;
		this.fullNameClaim = fullNameClaim;
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

					// new one 
					JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder();
					jwtConsumerBuilder
							.setAllowedClockSkewInSeconds(leewaySeconds);

					// new one
					if (jwksUrl != null && !jwksUrl.isEmpty() && jwksResolver == null) {
						jwksResolver = new HttpsJwksVerificationKeyResolver(
								new HttpsJwks(jwksUrl)
						);
					}

					if (jwksResolver != null) {
						jwtConsumerBuilder.setVerificationKeyResolver(jwksResolver);
					} else {
						// no jwks.. accept no signature
						jwtConsumerBuilder.setDisableRequireSignature();
						jwtConsumerBuilder.setSkipSignatureVerification();
					}

					// issuer restriction?
					if (acceptedIssuer != null && !acceptedIssuer.isEmpty()) {
						jwtConsumerBuilder.setExpectedIssuers(true, Util.tokenize(acceptedIssuer, ","));
					}

					// audience restriction?
					if (acceptedAudience != null && !acceptedAudience.isEmpty()) {
						jwtConsumerBuilder.setExpectedAudience(true, Util.tokenize(acceptedAudience, ","));
					} else {
						jwtConsumerBuilder.setSkipDefaultAudienceValidation();
					}

					JwtConsumer jwtConsumer = jwtConsumerBuilder.build();
					JwtClaims jwtClaims;

					try {
						jwtClaims = jwtConsumer.processToClaims(headerContent);
					} catch (Throwable t) {
						if (!allowVerificationFailures)	{
							throw t;
						}

						LOGGER.log(
							Level.SEVERE, "Verification error, but it is allowed by configuration", t
						);

						// re-run
						jwtConsumerBuilder.setSkipAllValidators();
						jwtConsumer = jwtConsumerBuilder.build();
						jwtClaims = jwtConsumer.processToClaims(headerContent);
					}

					// get username
					String username = jwtClaims.getClaimValueAsString(userClaimName);

					// get groups.. try as list first..
					List<String> groups;

					if (jwtClaims.isClaimValueStringList(groupsClaimName)) {
						groups = jwtClaims.getStringListClaimValue(groupsClaimName);
					} else {
						String groupList = jwtClaims.getClaimValueAsString(groupsClaimName);
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



                    User user = User.getById(username, true);

					if(fullNameClaim != null) {
						String fullName = jwtClaims.getClaimValueAsString(fullNameClaim);
						if (fullName != null) {
							user.setFullName(fullName);
						}
					}

					if(emailClaimName != null) {
						String email = jwtClaims.getClaimValueAsString(emailClaimName);
						if (email != null) {
							user.addProperty(new Mailer.UserProperty(email));
						}
					}
					user.save();

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
		public String getDefaultEmailClaimName() {
			return "email";
		}
		public String getDefaultFullNameClaim() {
			return "fullName";
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

	public String getAcceptedIssuer() {
		return acceptedIssuer;
	}

	public String getAcceptedAudience() {
		return acceptedAudience;
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
