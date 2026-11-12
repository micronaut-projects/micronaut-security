/*
 * Copyright 2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.mock;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.function.Consumer;

/**
 * An in-process OpenID provider exposing discovery metadata and a JSON Web Key Set, able to sign tokens with its key.
 */
public final class MockOpenIdProvider implements AutoCloseable {
    public static final String SPEC_NAME = "MockOpenIdProvider";
    public static final String ISSUER_PATH = "/oauth2/default";
    private static final RSAKey KEY = generateKey("mock-openid-provider");

    private final EmbeddedServer server;

    private MockOpenIdProvider(EmbeddedServer server) {
        this.server = server;
    }

    public static MockOpenIdProvider start() {
        return new MockOpenIdProvider(ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME)));
    }

    public String getIssuer() {
        return server.getURL() + ISSUER_PATH;
    }

    /**
     * @return The public JSON Web Key Set the provider publishes
     */
    public JWKSet jwkSet() {
        return new JWKSet(KEY.toPublicJWK());
    }

    /**
     * @param customizer Customizes the claims. By default, the token is issued by this provider and expires in one hour.
     * @return A serialized JWT signed with the provider's key
     */
    public String signedJwt(Consumer<JWTClaimsSet.Builder> customizer) {
        return signedJwt(KEY, customizer);
    }

    /**
     * @param customizer Customizes the claims
     * @return A serialized JWT issued by this provider but signed with a key the provider does not publish
     */
    public String signedJwtWithUnknownKey(Consumer<JWTClaimsSet.Builder> customizer) {
        return signedJwt(generateKey("unknown"), customizer);
    }

    private String signedJwt(RSAKey key, Consumer<JWTClaimsSet.Builder> customizer) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issuer(getIssuer())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)));
        customizer.accept(builder);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), builder.build());
        try {
            jwt.sign(new RSASSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.close();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;

        ProviderController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            String issuer = httpHostResolver.resolve(request) + ISSUER_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/v1/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/v1/token\","
                + "\"userinfo_endpoint\":\"" + issuer + "/v1/userinfo\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"response_types_supported\":[\"code\",\"id_token\",\"code id_token\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"scopes_supported\":[\"openid\",\"profile\",\"email\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        String keys() {
            return new JWKSet(KEY.toPublicJWK()).toString();
        }
    }
}
