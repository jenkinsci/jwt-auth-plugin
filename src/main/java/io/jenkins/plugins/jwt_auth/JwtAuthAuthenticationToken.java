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
