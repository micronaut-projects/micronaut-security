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
package io.micronaut.security.oauth2.endpoint.token.request.clientauth;

import org.reactivestreams.Publisher;

/**
 * Generates a signed JWT client assertion used for {@code private_key_jwt} client authentication at the token endpoint.
 *
 * <p>Implementations are qualified with {@code @Named} matching the OAuth 2.0 client name
 * (for example {@code @Named("my-client")}) to associate them with an OAuth 2.0 client configuration.</p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc10070.html#section-4">RFC 10070 - Updated JWT Client Authentication Requirements</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect Client Authentication</a>
 * @since 5.5.3
 */
@FunctionalInterface
public interface ClientAssertionGenerator {

    /**
     * The client assertion type of JWT bearer assertions.
     */
    String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * Generates a signed JWT assertion to authenticate against the token endpoint.
     *
     * <p>The JWT must contain the {@code iss} and {@code sub} (the client id), {@code aud}, {@code exp}, {@code iat}
     * and {@code jti} claims. The {@code aud} claim must contain only the authorization server's issuer identifier,
     * The returned publisher must be cold.</p>
     *
     * @param clientId The OAuth 2.0 client id
     * @param issuerIdentifier The authorization server's issuer identifier, used as the sole audience
     * @return A publisher emitting the serialized signed JWT
     */
    Publisher<String> generateAssertion(String clientId, String issuerIdentifier);
}
