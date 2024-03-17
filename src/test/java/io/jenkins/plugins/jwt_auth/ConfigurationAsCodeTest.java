package io.jenkins.plugins.jwt_auth;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigurationAsCodeTest {

  @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

  @Test
  @ConfiguredWithCode("configuration-as-code.yml")
  public void should_support_configuration_as_code() {

    Jenkins jenkins = r.jenkins;
    SecurityRealm realm = jenkins.getSecurityRealm();

    assertTrue(realm instanceof JwtAuthSecurityRealm);

    JwtAuthSecurityRealm jwtAuthSecurityRealm = (JwtAuthSecurityRealm) realm;
    assertEquals(
        "jwt-token-header",
        jwtAuthSecurityRealm.getHeaderName()
    );
    assertEquals(
        "username",
        jwtAuthSecurityRealm.getUserClaimName()
    );
    assertEquals(
        "groups",
        jwtAuthSecurityRealm.getGroupsClaimName()
    );
    assertEquals(
        "-",
        jwtAuthSecurityRealm.getGroupsClaimSeparator()
    );
    assertEquals(
        "myIssuer",
        jwtAuthSecurityRealm.getAcceptedIssuer()
    );
    assertEquals(
        "myAudience",
        jwtAuthSecurityRealm.getAcceptedAudience()
    );
    assertEquals(
        "http://jwks-host/.well-known/openid",
        jwtAuthSecurityRealm.getJwksUrl()
    );
    assertEquals(
        3,
        jwtAuthSecurityRealm.getLeewaySeconds()
    );
    assertTrue(jwtAuthSecurityRealm.isAllowVerificationFailures());
    assertEquals(
        "email",
        jwtAuthSecurityRealm.getEmailClaimName()
    );
    assertEquals(
        "name",
        jwtAuthSecurityRealm.getFullNameClaim()
    );
    assertEquals(
        "http://jwks-host/login",
        jwtAuthSecurityRealm.getLoginUrl()
    );
  }
}
