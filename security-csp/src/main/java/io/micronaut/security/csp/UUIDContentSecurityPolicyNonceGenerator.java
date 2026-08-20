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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import jakarta.inject.Singleton;

import java.util.UUID;

/**
 * Default nonce generator backed by a randomly generated UUID.
 *
 * <p>This bean is used only when an application does not provide its own
 * {@link ContentSecurityPolicyNonceGenerator} implementation.</p>
 */
@Requires(missingBeans =  ContentSecurityPolicyNonceGenerator.class)
@Singleton
@Internal
final class UUIDContentSecurityPolicyNonceGenerator implements ContentSecurityPolicyNonceGenerator {
    @Override
    public String generateNonce(HttpRequest<?> request) {
        return UUID.randomUUID().toString();
    }
}
