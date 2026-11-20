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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import jakarta.inject.Singleton;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default nonce generator: 144 bits from {@link SecureRandom}, base64-encoded to 24 characters.
 *
 * <p>CSP recommends nonces of at least 128 bits encoded as base64. 18 bytes encode without padding.</p>
 *
 * <p>This bean is used only when an application does not provide its own
 * {@link ContentSecurityPolicyNonceGenerator} implementation. A replacement generator must return
 * a fresh, unpredictable value for each request; reusing a nonce weakens nonce-based script policies.</p>
 */
@Requires(missingBeans = ContentSecurityPolicyNonceGenerator.class)
@Singleton
@Internal
final class SecureRandomContentSecurityPolicyNonceGenerator implements ContentSecurityPolicyNonceGenerator {
    private static final int NONCE_BYTES = 18;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generateNonce(HttpRequest<?> request) {
        byte[] bytes = new byte[NONCE_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
