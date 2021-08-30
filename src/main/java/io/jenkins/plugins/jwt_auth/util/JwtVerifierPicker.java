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

package io.jenkins.plugins.jwt_auth.util;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class JwtVerifierPicker {

  public static JWTVerifier getVerifier(Jwk jwk, int leewaySeconds) throws InvalidPublicKeyException {
    Algorithm algorithm;
    PublicKey publicKey = jwk.getPublicKey();

    switch (jwk.getAlgorithm().toUpperCase()) {
      case "HS256":
        algorithm = Algorithm.HMAC256(publicKey.getEncoded());
        break;
      case "HS384":
        algorithm = Algorithm.HMAC384(publicKey.getEncoded());
        break;
      case "HS512":
        algorithm = Algorithm.HMAC512(publicKey.getEncoded());
        break;
      case "RS256":
        algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
        break;
      case "RS384":
        algorithm = Algorithm.RSA384((RSAPublicKey) publicKey, null);
        break;
      case "RS512":
        algorithm = Algorithm.RSA512((RSAPublicKey) publicKey, null);
        break;
      case "ES256":
        algorithm = Algorithm.ECDSA256((ECPublicKey) publicKey, null);
        break;
      case "ES256K":
        algorithm = Algorithm.ECDSA256K((ECPublicKey) publicKey, null);
        break;
      case "ES384":
        algorithm = Algorithm.ECDSA384((ECPublicKey) publicKey, null);
        break;
      case "ES512":
        algorithm = Algorithm.ECDSA512((ECPublicKey) publicKey, null);
        break;
      default:
        throw new IllegalStateException("Unexpected algorithm value: " + jwk.getAlgorithm().toUpperCase());
    }

    return JWT.require(algorithm).acceptLeeway(leewaySeconds).build();
  }

}
