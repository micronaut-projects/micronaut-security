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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.authentication=idtoken} the attributes of the authentication are the claims of the ID token,
 * and {@code /oauth/logout} trusts the {@code oauth2Provider} attribute, which only the application sets, to pick the provider.
 * An ID token carrying a claim with a reserved attribute name must therefore not authenticate.
 */
class IdTokenClaimsValidatorReservedClaimsTest {
    private static final String ISSUER = "https://issuer.example.com";
    private static final String CLIENT_ID = "client-id-test-fixture-not-a-secret";

    private static ApplicationContext context;

    @BeforeAll
    static void startContext() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.oauth2.clients.self.client-id", CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.self.client-secret", "test-fixture-not-a-secret");
        // on this branch discovery is fetched at startup: point it at a closed port so it fails fast
        configuration.put("micronaut.security.oauth2.clients.self.openid.issuer", "http://localhost:1/oauth2/default");
        configuration.put("micronaut.security.oauth2.clients.self.openid.issuer-identifier", ISSUER);
        context = ApplicationContext.run(configuration);
    }

    @AfterAll
    static void stopContext() {
        context.close();
    }

    @Test
    void tokenWithoutReservedClaimsIsAccepted() {
        assertTrue(validator().validate(claims(null, null), null));
    }

    @Test
    void tokenCarryingTheProviderAttributeNameIsRejected() {
        assertFalse(validator().validate(claims(OauthAuthenticationMapper.PROVIDER_KEY, "other"), null));
        assertFalse(validator().validate(claims(OauthAuthenticationMapper.PROVIDER_KEY, "self"), null), "the reserved name is rejected whatever its value");
    }

    @Test
    void tokenCarryingTheOpenIdTokenAttributeNameIsRejected() {
        assertFalse(validator().validate(claims(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, "any-value"), null));
    }

    private static JwtClaimsSetAdapter claims(String extraClaim, String value) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(CLIENT_ID)
            .subject("sherlock");
        if (extraClaim != null) {
            builder.claim(extraClaim, value);
        }
        return new JwtClaimsSetAdapter(builder.build());
    }

    private static IdTokenClaimsValidator validator() {
        return new IdTokenClaimsValidator(Collections.singletonList(context.getBean(OauthClientConfiguration.class)));
    }
}
