package io.jenkins.plugins.jwt_auth;

// for reference https://www.wwt.com/article/automated-testing-with-spring-boot-as-an-oauth2-resource-server/
// https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.google.common.collect.ImmutableList;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@RunWith(Parameterized.class)
public class JwtAuthSecurityRealmTest {

    @ClassRule
    public static WireMockRule wireMockRule = new WireMockRule(WireMockConfiguration.options().port(9999));

    public static RsaJsonWebKey rsaJwk;
    public static EllipticCurveJsonWebKey ecJwk;

    @Rule
    public final JenkinsRule jenkinsRule = new JenkinsRule();

    private Jenkins jenkins;

    /* test params */
    private String headerName;
    private String userClaimName;
    private String groupClaimName;
    private String groupClaimSeparator;
    private String keyId;
    private Algorithm algorithm;
    private String expectedUser;
    private List<String> expectedGroups;

    @Before
    public void prepare() {
        jenkins = jenkinsRule.jenkins;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws JoseException {
        rsaJwk = RsaJwkGenerator.generateJwk(2048);
        rsaJwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        rsaJwk.setKeyId("id1");

        ecJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        ecJwk.setKeyId("id2");

        JsonWebKeySet jwks = new JsonWebKeySet(rsaJwk, ecJwk);

        String jwksJson = jwks.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);

        wireMockRule.stubFor(
                WireMock.get(WireMock.urlEqualTo("/.well-known/jwks.json"))
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksJson)
                        )
        );

        return ImmutableList.of(
                // normal use case with rsa key
                new Object[]{
                        "Authorization",
                        "username",
                        "groups",
                        "",
                        "id1",
                        Algorithm.RSA256(rsaJwk.getRsaPublicKey(), rsaJwk.getRsaPrivateKey()),
                        "testuser",
                        List.of("hans")
                },
                // normal use case with ec key
                new Object[]{
                        "Authorization",
                        "username",
                        "groups",
                        "",
                        "id2",
                        Algorithm
                        "testuser",
                        List.of("hans")
                }
        );

    }

    public JwtAuthSecurityRealmTest(
            String headerName,
            String userClaimName,
            String groupClaimName,
            String groupClaimSeparator,
            String keyId,
            Algorithm signAlgo,
            String expectedUserName,
            List<String> expectedGroupList
    ) {
        this.headerName = headerName;
        this.userClaimName = userClaimName;
        this.groupClaimName = groupClaimName;
        this.groupClaimSeparator = groupClaimSeparator;
        this.keyId = keyId;
        this.algorithm = signAlgo;
        this.expectedUser = expectedUserName;
        this.expectedGroups = expectedGroupList;
    }

    @Test
    public void testSecurityRealm() throws Exception {

        JwtAuthSecurityRealm realm = new JwtAuthSecurityRealm(
                headerName,
                userClaimName,
                groupClaimName,
                groupClaimSeparator,
                "http://localhost:9999/.well-known/jwks.json",
                0,
                false
        );
        jenkins.setSecurityRealm(realm);

        String token = JWT.create()
                .withIssuer("test")
                .withKeyId(keyId)
                .withClaim(userClaimName, expectedUser)
                .withClaim(groupClaimName, expectedGroups)
                .sign(algorithm);

        final JenkinsRule.WebClient client = jenkinsRule.createWebClient();
        client.addRequestHeader(headerName, token);

        final Authentication authentication = client.executeOnServer(Jenkins::getAuthentication2);

        List<GrantedAuthority> groups = new ArrayList<>();
        groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        for (String groupName : expectedGroups) {
            groups.add(new SimpleGrantedAuthority(groupName));
        }

        Assert.assertEquals(expectedUser, authentication.getName());

        Assert.assertEquals(groups.size(), authentication.getAuthorities().size());
        Assert.assertTrue(groups.containsAll(authentication.getAuthorities()));
    }
}
