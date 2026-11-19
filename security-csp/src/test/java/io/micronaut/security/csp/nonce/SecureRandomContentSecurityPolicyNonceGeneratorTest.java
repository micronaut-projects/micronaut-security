/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.csp.nonce;

import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureRandomContentSecurityPolicyNonceGeneratorTest {
    /** The CSP base64-value grammar that the default policy generator accepts for nonces. */
    private static final Pattern NONCE_GRAMMAR = Pattern.compile("[A-Za-z0-9+/_-]+={0,2}");
    private static final int NONCES = 100;

    @Test
    void generatesDistinctNoncesThatTheGeneratorAccepts() {
        ContentSecurityPolicyNonceGenerator generator = new SecureRandomContentSecurityPolicyNonceGenerator();
        Set<String> nonces = new HashSet<>();

        for (int i = 0; i < NONCES; i++) {
            String nonce = generator.generateNonce(HttpRequest.GET("/"));
            assertTrue(NONCE_GRAMMAR.matcher(nonce).matches(), () -> "nonce outside the CSP base64-value grammar: " + nonce);
            assertEquals(18, Base64.getDecoder().decode(nonce).length, "a nonce carries 144 random bits");
            nonces.add(nonce);
        }

        assertEquals(NONCES, nonces.size(), "nonces must not repeat");
    }
}
