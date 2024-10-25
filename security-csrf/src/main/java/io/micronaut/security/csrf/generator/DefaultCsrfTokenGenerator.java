/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.session.SessionIdResolver;
import io.micronaut.security.utils.HMacUtils;
import jakarta.inject.Singleton;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default implementation of {@link CsrfTokenGenerator} which generates a CSRF Token prefixed by an HMAC if a secret key is set.
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#pseudo-code-for-implementing-hmac-csrf-tokens">Pseudo Code for implementing hmac CSRF tokens</a>
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> Request
 */
@Requires(classes = CookieConfiguration.class)
@Singleton
final class DefaultCsrfTokenGenerator<T> implements CsrfHmacTokenGenerator<T> {
    /**
     * hmac random value separator.
     */
    private static final String SESSION_RANDOM_SEPARATOR = "!";
    private final SecureRandom secureRandom = new SecureRandom();
    private final CsrfConfiguration csrfConfiguration;
    private final SessionIdResolver<T> sessionIdResolver;

    /**
     *
     * @param csrfConfiguration CSRF Configuration
     * @param sessionIdResolver SessionID Resolver
     */
    DefaultCsrfTokenGenerator(CsrfConfiguration csrfConfiguration,
                              SessionIdResolver<T> sessionIdResolver) {
        this.csrfConfiguration = csrfConfiguration;
        this.sessionIdResolver = sessionIdResolver;
    }

    @Override
    @NonNull
    public String generateCsrfToken(@NonNull T request) {
        byte[] tokenBytes = new byte[csrfConfiguration.getRandomValueSize()];
        secureRandom.nextBytes(tokenBytes);
        String randomValue = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);  // Cryptographic random value

        String hmac = hmac(request, randomValue);
        // Add the `randomValue` to the HMAC hash to create the final CSRF token. Avoid using the `message` because it contains the sessionID in plain text, which the server already stores separately.
        return  hmac + HMAC_RANDOM_SEPARATOR + randomValue;
    }

    /**
     *
     * @param request Request
     * @param base64EncodedRandomValue Cryptographic random value encoded as Base64
     * @return HMAC hash
     */
    @Override
    @NonNull
    public String hmac(@NonNull T request, @NonNull  String base64EncodedRandomValue) {
        // Gather the values
        String secret = csrfConfiguration.getSecretKey();
        String sessionID = sessionIdResolver.findSessionId(request).orElse(""); // Current authenticated user session

        // Create the CSRF Token
        String message = hmacMessagePayload(sessionID, base64EncodedRandomValue);
        try {
            return StringUtils.isNotEmpty(secret)
                    ? HMacUtils.base64EncodedHmacSha256(message, secret) // Generate the HMAC hash
                    : "";
        } catch (InvalidKeyException ex) {
            throw new ConfigurationException("Invalid secret key for signing the CSRF token");
        } catch (NoSuchAlgorithmException ex) {
            throw new ConfigurationException("Invalid algorithm for signing the CSRF token");
        }
    }

    static String hmacMessagePayload(String sessionId, String randomValue) {
        // both session id and randomValue will be base64 encoded strings to ensure they don't contain the separator ! as a substring.
        final String base64SessionId = Base64.getEncoder().encodeToString(sessionId.getBytes());
        return  base64SessionId.length() +
                SESSION_RANDOM_SEPARATOR +
                base64SessionId +
                SESSION_RANDOM_SEPARATOR +
                randomValue.length() +
                SESSION_RANDOM_SEPARATOR +
                randomValue;
    }
}
