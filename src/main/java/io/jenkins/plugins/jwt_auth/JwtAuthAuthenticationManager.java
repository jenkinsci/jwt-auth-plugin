package io.jenkins.plugins.jwt_auth;

import jenkins.security.SecurityListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

//public class JwtAuthAuthenticationManager implements AuthenticationManager  {
//
//  @Override
//  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//    JwtAuthAuthenticationToken token = new JwtAuthAuthenticationToken();
//    SecurityContextHolder.getContext().setAuthentication(token);
//    SecurityListener.fireAuthenticated2(new JwtAuthUserDetails(token.getName(), token.getAuthorities()));
//
//    return token;
//  }
//}
