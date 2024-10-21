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
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.session.SessionIdResolver;
import io.micronaut.security.utils.HMacUtils;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Default implementation of {@link CsrfTokenGenerator} which generates a random base 64 encoded string using an instance of {@link SecureRandom} and random byte array of size {@link CsrfConfiguration#getRandomValueSize()}.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
@Internal
final class DefaultCsrfTokenGenerator implements CsrfTokenGenerator<HttpRequest<?>>, CsrfTokenValidator<HttpRequest<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultCsrfTokenGenerator.class);
    private static final String SESSION_RANDOM_SEPARATOR = "!";
    private static final String HMAC_RANDOM_SEPARATOR = ".";
    private final SecureRandom secureRandom = new SecureRandom();
    private final CsrfConfiguration csrfConfiguration;
    private final SessionIdResolver<HttpRequest<?>> sessionIdResolver;

    DefaultCsrfTokenGenerator(CsrfConfiguration csrfConfiguration,
                              SessionIdResolver<HttpRequest<?>> sessionIdResolver) {
        this.csrfConfiguration = csrfConfiguration;
        this.sessionIdResolver = sessionIdResolver;
    }

    @Override
    public String generate(HttpRequest<?> request) {
        // Gather the values
        String secret = csrfConfiguration.getSecretKey();
        String sessionID = sessionIdResolver.findSessionId(request).orElse(""); // Current authenticated user session
        byte[] tokenBytes = new byte[csrfConfiguration.getRandomValueSize()];
        secureRandom.nextBytes(tokenBytes);
        String randomValue = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);  // Cryptographic random value

        // Create the CSRF Token
        String message = sessionID + SESSION_RANDOM_SEPARATOR + randomValue; // HMAC message payload
        try {
            String hmac = secret != null
                    ? HMacUtils.base64EncodedHmacSha256(message, secret) // Generate the HMAC hash
                    : "";
            // Add the `randomValue` to the HMAC hash to create the final CSRF token. Avoid using the `message` because it contains the sessionID in plain text, which the server already stores separately.
            return  hmac + HMAC_RANDOM_SEPARATOR + randomValue;
        } catch (InvalidKeyException ex) {
            throw new ConfigurationException("Invalid secret key for signing the CSRF token");
        } catch (NoSuchAlgorithmException ex) {
            throw new ConfigurationException("Invalid algorithm for signing the CSRF token");
        }
    }

    @Override
    public boolean validateCsrfToken(@NonNull HttpRequest<?> request, @NonNull String token) {
        Optional<String> csrfCookieOptional = findCsrfToken(request);
        if (csrfCookieOptional.isEmpty()) {
            return false;
        }
        String csrfCookie =  csrfCookieOptional.get();
        return csrfCookie.equals(token) && validateHmac(request, csrfCookie);
    }

    private boolean validateHmac(HttpRequest<?> request, @NonNull String csrfToken) {
        try {
            String[] arr = csrfToken.split("\\.");
            if (arr.length != 2) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Invalid CSRF token: {}", csrfToken);
                }
                return false;
            }
            String hmac = arr[0];
            String randomValue = arr[1];
            String sessionID = sessionIdResolver.findSessionId(request).orElse(""); // Current authenticated user session
            String message = sessionID + SESSION_RANDOM_SEPARATOR + randomValue;
            String secret = csrfConfiguration.getSecretKey();
            String expectedHmac = secret != null
                    ? HMacUtils.base64EncodedHmacSha256(message, secret) // Generate the HMAC hash
                    : "";
            return hmac.contains(expectedHmac);
        } catch (InvalidKeyException ex) {
            throw new ConfigurationException("Invalid secret key for signing the CSRF token");
        } catch (NoSuchAlgorithmException ex) {
            throw new ConfigurationException("Invalid algorithm for signing the CSRF token");
        }
    }

    private Optional<String> findCsrfToken(HttpRequest<?> request) {
        return request.getCookies()
                .findCookie(csrfConfiguration.getCookieName())
                .map(Cookie::getValue);
    }
}
