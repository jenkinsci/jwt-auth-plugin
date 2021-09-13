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

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
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
    public static WireMockRule wireMockRule = new WireMockRule(WireMockConfiguration.options().port(9191));

    public static RsaJsonWebKey rsaJwk;
    public static EllipticCurveJsonWebKey ecJwk;

    @Rule
    public final JenkinsRule jenkinsRule = new JenkinsRule();

    private Jenkins jenkins;

    /* test params */
    private String jwksUrl;
    private String acceptableIssuer;
    private String acceptableAudience;
    private String headerName;
    private String userClaimName;
    private String groupClaimName;
    private String groupClaimSeparator;
    private PublicJsonWebKey jsonWebKey;
    private String usernameHeaderValue;
    private String expectedUser;
    private List<String> expectedGroups;
    private boolean allowVerificationFailures;
    private String groupListString;

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
        ecJwk.setAlgorithm(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
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

        return Arrays.asList(
                // normal use case with rsa key
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "",
                        "",
                        "Authorization",
                        "username",
                        "groups",
                        "",
                        rsaJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("hans"),
                        null,
                        false
                },
                // normal use case with ec key
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "",
                        "",
                        "custom-header-name",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("hans"),
                        null,
                        false
                },
                // ec key, group list as string with separator
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "",
                        "",
                        "other-header-NAME",
                        "username",
                        "string-group-field",
                        "|",
                        ecJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("group1", "group2", "group3"),
                        "group1|group2|group3",
                        false
                },
                // no jwks defined in the realm
                new Object[]{
                        "",
                        "",
                        "",
                        "other-header-NAME",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("group1"),
                        null,
                        false
                },
                // audience and issuer matching
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "issuer1,test",
                        "audience1,testaudience",
                        "other-header-NAME",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("group1"),
                        null,
                        false
                },
                // audience not matching -> anonymous
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "issuer1,test",
                        "audience1",
                        "other-header-NAME",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        Jenkins.ANONYMOUS2.getName(),
                        Arrays.asList(), // groups not added
                        null,
                        false
                },
                // issuer not matching
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "issuer1",
                        "audience1,testaudience",
                        "other-header-NAME",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        Jenkins.ANONYMOUS2.getName(),
                        Arrays.asList(), // groups not added
                        null,
                        false
                },
                // issuer not matching, but verification errors are allowed
                new Object[]{
                        "http://localhost:9191/.well-known/jwks.json",
                        "issuer1",
                        "audience1,testaudience",
                        "other-header-NAME",
                        "username",
                        "groups",
                        "",
                        ecJwk,
                        "testuser",
                        "testuser",
                        Arrays.asList("groups1"), // groups not added
                        null,
                        true // is allowed!
                }
        );

    }

    public JwtAuthSecurityRealmTest(
            String jwksUrl,
            String acceptableIssuer,
            String acceptableAudience,
            String headerName,
            String userClaimName,
            String groupClaimName,
            String groupClaimSeparator,
            PublicJsonWebKey jsonWebKey,
            String usernameHeaderValue,
            String expectedUserName,
            List<String> expectedGroupList,
            String groupListString,
            boolean allowVerificationFailures
    ) {
        this.jwksUrl = jwksUrl;
        this.acceptableIssuer = acceptableIssuer;
        this.acceptableAudience = acceptableAudience;
        this.headerName = headerName;
        this.userClaimName = userClaimName;
        this.groupClaimName = groupClaimName;
        this.groupClaimSeparator = groupClaimSeparator;
        this.jsonWebKey = jsonWebKey;
        this.usernameHeaderValue = usernameHeaderValue;
        this.expectedUser = expectedUserName;
        this.expectedGroups = expectedGroupList;
        this.groupListString = groupListString;
        this.allowVerificationFailures = allowVerificationFailures;
    }

    @Test
    public void testSecurityRealm() throws Exception {

        JwtAuthSecurityRealm realm = new JwtAuthSecurityRealm(
                headerName,
                userClaimName,
                groupClaimName,
                groupClaimSeparator,
                acceptableIssuer,
                acceptableAudience,
                jwksUrl,
                0,
                allowVerificationFailures
        );
        jenkins.setSecurityRealm(realm);

        JwtClaims claims = new JwtClaims();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setIssuer("test");
        claims.setAudience("testaudience");
        claims.setStringClaim(userClaimName, usernameHeaderValue);

        // list or string type for groups?
        if (groupListString != null) {
            claims.setStringClaim(groupClaimName, groupListString);
        } else {
            claims.setStringListClaim(groupClaimName, expectedGroups);
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(jsonWebKey.getPrivateKey());
        jws.setKeyIdHeaderValue(jsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(jsonWebKey.getAlgorithm());

        final JenkinsRule.WebClient client = jenkinsRule.createWebClient();
        client.addRequestHeader(headerName, jws.getCompactSerialization());

        final Authentication authentication = client.executeOnServer(Jenkins::getAuthentication2);

        Assert.assertEquals(expectedUser, authentication.getName());

        Collection<GrantedAuthority> groups = new ArrayList<>();
        if (authentication.getName().equals(Jenkins.ANONYMOUS2.getName())) {
            groups.addAll(Jenkins.ANONYMOUS2.getAuthorities());
        } else {
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        }

        for (String groupName : expectedGroups) {
            groups.add(new SimpleGrantedAuthority(groupName));
        }

        Assert.assertEquals(groups.size(), authentication.getAuthorities().size());
        Assert.assertTrue(groups.containsAll(authentication.getAuthorities()));
    }
}
