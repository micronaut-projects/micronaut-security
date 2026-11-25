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
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.session.SessionIdResolver;
import io.micronaut.security.utils.HMacUtils;
import jakarta.inject.Singleton;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default implementation of {@link CsrfTokenGenerator} which generates a CSRF Token prefixed by an HMAC if a secret key is set.
 * The HMAC binds the token to the session identifier resolved via {@link SessionIdResolver} and to the name of the
 * authenticated user, so that a token issued to one user is not valid for a request authenticated as another user.
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
        return generateCsrfToken(request, resolveAuthentication(request));
    }

    @Override
    @NonNull
    public String generateCsrfToken(@NonNull T request, @Nullable Authentication authentication) {
        byte[] tokenBytes = new byte[csrfConfiguration.getRandomValueSize()];
        secureRandom.nextBytes(tokenBytes);
        String randomValue = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);  // Cryptographic random value

        String hmac = hmac(request, authentication, randomValue);
        // Add the `randomValue` to the HMAC hash to create the final CSRF token. Avoid using the `message` because it contains the sessionID in plain text, which the server already stores separately.
        return  hmac + HMAC_RANDOM_SEPARATOR + randomValue;
    }

    /**
     * Generates an HMAC bound to the session and to the user authenticated in the request.
     * @param request Request
     * @param base64EncodedRandomValue Cryptographic random value encoded as Base64
     * @return HMAC hash
     */
    @Override
    @NonNull
    public String hmac(@NonNull T request, @NonNull  String base64EncodedRandomValue) {
        return hmac(request, resolveAuthentication(request), base64EncodedRandomValue);
    }

    @Override
    @NonNull
    public String hmac(@NonNull T request, @Nullable Authentication authentication, @NonNull String base64EncodedRandomValue) {
        // Gather the values
        String secret = csrfConfiguration.getSecretKey();
        String sessionID = sessionIdResolver.findSessionId(request).orElse(""); // Current authenticated user session
        String username = userIdentifier(authentication); // Current authenticated user

        // Create the CSRF Token
        String message = hmacMessagePayload(sessionID, username, base64EncodedRandomValue);
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

    /**
     * The identifier bound into the HMAC: the canonical name of the principal, {@link Authentication#getName()}.
     * Attributes are not used, since distinct principals may share attribute values: for example, authentications
     * validated via an OpenID provider UserInfo endpoint are named {@code providerName:sub} and may share the raw
     * {@code sub} or the {@code email} attribute, and such principals must not share CSRF tokens.
     * <p>
     * Login handlers issuing a token supply the {@link Authentication} named as token based authentication names the
     * user on later requests (the {@code micronaut.security.token.name-key} claim, falling back to the {@code sub} claim,
     * which is the principal name), so the value computed at login equals the one computed on later requests.
     * @param authentication The authentication or {@code null} for an anonymous request
     * @return The identifier, an empty string for an anonymous request or an authentication without a name
     */
    @NonNull
    private static String userIdentifier(@Nullable Authentication authentication) {
        if (authentication == null) {
            return "";
        }
        String name = authentication.getName();
        return name != null ? name : "";
    }

    /**
     * @param request Request
     * @return The authenticated user associated with the request, or {@code null} for an anonymous request
     */
    @Nullable
    private static Authentication resolveAuthentication(@NonNull Object request) {
        if (request instanceof HttpRequest<?> httpRequest) {
            return ServerRequestContextSecurityContextSupplier.getSecurityContext(httpRequest).getAuthentication();
        }
        return SecurityContextHolder.getSecurityContext().getAuthentication();
    }

    static String hmacMessagePayload(String sessionId, String username, String randomValue) {
        // session id, username and randomValue will be base64 encoded strings to ensure they don't contain the separator ! as a substring.
        final String base64SessionId = Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
        final String base64Username = Base64.getEncoder().encodeToString(username.getBytes(StandardCharsets.UTF_8));
        return  base64SessionId.length() +
                SESSION_RANDOM_SEPARATOR +
                base64SessionId +
                SESSION_RANDOM_SEPARATOR +
                base64Username.length() +
                SESSION_RANDOM_SEPARATOR +
                base64Username +
                SESSION_RANDOM_SEPARATOR +
                randomValue.length() +
                SESSION_RANDOM_SEPARATOR +
                randomValue;
    }
}
