package io.jenkins.plugins.jwt_auth;

import hudson.security.SecurityRealm;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class JwtAuthAuthenticationToken extends AbstractAuthenticationToken {

  private final String username;

  public static JwtAuthAuthenticationToken createInstance(String username, List<String> groups) {
    List<GrantedAuthority> roles = new ArrayList<>();
    roles.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

    groups.forEach(group -> {
      roles.add(new SimpleGrantedAuthority(group));
    });

    return new JwtAuthAuthenticationToken(username, roles);
  }

  public JwtAuthAuthenticationToken(String username, Collection<? extends GrantedAuthority> groups) {
    super(groups);
    this.username = username;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return new JwtAuthUserDetails(username, getAuthorities());
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }
}
