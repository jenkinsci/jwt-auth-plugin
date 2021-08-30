package io.jenkins.plugins.jwt_auth;

// for reference https://www.wwt.com/article/automated-testing-with-spring-boot-as-an-oauth2-resource-server/
// https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.net.MalformedURLException;
import java.util.concurrent.Callable;
import jenkins.model.Jenkins;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;

public class JwtAuthSecurityRealmTest {

  @ClassRule
  public static WireMockRule wireMockRule = new WireMockRule(WireMockConfiguration.options().port(9999));

  @Rule
  public final JenkinsRule jenkinsRule = new JenkinsRule();

  public static RsaJsonWebKey rsaJwk1;
  public static RsaJsonWebKey rsaJwk2;

  private Jenkins jenkins;

  @BeforeClass
  public static void prepare() throws JoseException {
    rsaJwk1 = RsaJwkGenerator.generateJwk(2048);
    rsaJwk1.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
    rsaJwk1.setKeyId("id1");
    rsaJwk2 = RsaJwkGenerator.generateJwk(2048);
    rsaJwk2.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
    rsaJwk2.setKeyId("id2");
    EllipticCurveJsonWebKey ecJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);

    JsonWebKeySet jwks = new JsonWebKeySet(rsaJwk1, rsaJwk2, ecJwk);

    String jwksJson = jwks.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);

    wireMockRule.stubFor(
        WireMock.get(WireMock.urlEqualTo("/.well-known/jwks.json"))
            .willReturn(
                WireMock.aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(jwksJson)
            )
    );
  }

  @Before
  public void setUp() {
    jenkins = jenkinsRule.jenkins;
  }

  @Test
  public void testBasicHandling() throws Exception {
    JwtAuthSecurityRealm realm = new JwtAuthSecurityRealm(
      "Authorization",
      "user",
      "group",
      "",
      "http://localhost:9999/.well-known/jwks.json",
        0,
        false
    );
    jenkins.setSecurityRealm(realm);

    // create token
    Algorithm algorithmRS = Algorithm.RSA256(rsaJwk1.getRsaPublicKey(), rsaJwk2.getRsaPrivateKey());

    String token = JWT.create()
        .withIssuer("test")
        .withKeyId("id1")
        .withClaim("user", "testuser")
        .withClaim("group", "hans")
        .sign(algorithmRS);

    final JenkinsRule.WebClient client = jenkinsRule.createWebClient();
    client.addRequestHeader("Authorization", token);

    final Authentication authentication = client.executeOnServer(new Callable<Authentication>() {
      @Override
      public Authentication call() {
        return Jenkins.getAuthentication2();
      }
    });

    int hans = 3;

  }

}
