/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PKCEPersistence;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * A default PKCE provider that creates and persist the Proof of Key Exchange parameters.
 *
 * @author Nemanja Mikic
 * @since 3.8.0
 */
@Singleton
@Requires(beans = PKCEPersistence.class)
public class DefaultPKCEFactory implements PKCEFactory {

    /**
     * SHA-256 based code verifier challenge method.
     *
     * @see "Proof Key for Code Exchange by OAuth Public Clients (RFC 7636), Section 4.3
     * <https://tools.ietf.org/html/rfc7636#section-4.3>"
     */
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    /**
     * Plain-text code verifier challenge method. This is only used by AppAuth for Android if
     * SHA-256 is not supported on this platform.
     *
     * @see "Proof Key for Code Exchange by OAuth Public Clients (RFC 7636), Section 4.4
     * <https://tools.ietf.org/html/rfc7636#section-4.4>"
     */
    public static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";

    /**
     * The default entropy (in bytes) used for the code verifier.
     */
    public static final int DEFAULT_CODE_VERIFIER_ENTROPY = 64;

    private static final Logger LOG = LoggerFactory.getLogger(DefaultPKCEFactory.class);

    private final PKCEPersistence pkcePersistence;

    /**
     * @param pkcePersistence A PKCE persistence
     */
    public DefaultPKCEFactory(PKCEPersistence pkcePersistence) {
        this.pkcePersistence = pkcePersistence;
    }

    /**
     * Generates a random code verifier string using {@link SecureRandom} as the source of
     * entropy, with the default entropy quantity as defined by
     * {@link #DEFAULT_CODE_VERIFIER_ENTROPY}.
     *
     * @return String the generated code verifier
     */
    public static String generateRandomCodeVerifier() {
        return generateRandomCodeVerifier(new SecureRandom(), DEFAULT_CODE_VERIFIER_ENTROPY);
    }

    /**
     * Generates a random code verifier string using the provided entropy source and the specified
     * number of bytes of entropy.
     *
     * @param entropySource entropy source
     * @param entropyBytes  entropy bytes
     * @return String generated code verifier
     */
    public static String generateRandomCodeVerifier(SecureRandom entropySource, int entropyBytes) {
        byte[] randomBytes = new byte[entropyBytes];
        entropySource.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Produces a challenge from a code verifier, using SHA-256 as the challenge method if the
     * system supports it (all Android devices _should_ support SHA-256), and falls back
     * to the "plain" challenge type if unavailable.
     *
     * @param codeVerifier code verifier
     * @return String derived challenge
     */
    public static String deriveCodeVerifierChallenge(String codeVerifier) {
        try {
            MessageDigest sha256Digester = MessageDigest.getInstance("SHA-256");
            sha256Digester.update(codeVerifier.getBytes("ISO_8859_1"));
            byte[] digestBytes = sha256Digester.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digestBytes);
        } catch (NoSuchAlgorithmException e) {
            LOG.warn("SHA-256 is not supported on this device! Using plain challenge", e);
            return codeVerifier;
        } catch (UnsupportedEncodingException e) {
            LOG.error("ISO-8859-1 encoding not supported on this device!", e);
            throw new IllegalStateException("ISO-8859-1 encoding not supported", e);
        }
    }

    /**
     * Returns the challenge method utilized on this system: typically SHA-256 if supported by
     * the system, plain otherwise.
     *
     * @return String challenge method
     */
    public static String getCodeVerifierChallengeMethod() {
        try {
            MessageDigest.getInstance("SHA-256");
            // no exception, so SHA-256 is supported
            return CODE_CHALLENGE_METHOD_S256;
        } catch (NoSuchAlgorithmException e) {
            return CODE_CHALLENGE_METHOD_PLAIN;
        }
    }

    @SuppressWarnings("rawtypes")
    @Nullable
    @Override
    public PKCE buildPKCE(HttpRequest<?> request, MutableHttpResponse response, AuthorizationRequest authorizationRequest) {
        PKCE pkce = createInitialState();
        pkcePersistence.persistPKCE(request, response, pkce);
        return pkce;
    }

    /**
     * @return The mutable state to further modify
     */
    protected PKCE createInitialState() {
        DefaultPKCE defaultPKCE = new DefaultPKCE();
        defaultPKCE.setCodeVerifier(generateRandomCodeVerifier());
        defaultPKCE.setCodeMethod(getCodeVerifierChallengeMethod());
        if (defaultPKCE.getCodeMethod().equals(CODE_CHALLENGE_METHOD_S256)) {
            defaultPKCE.setCodeChallenge(deriveCodeVerifierChallenge(defaultPKCE.getCodeVerifier()));
        }
        if (defaultPKCE.getCodeMethod().equals(CODE_CHALLENGE_METHOD_PLAIN)) {
            defaultPKCE.setCodeChallenge(defaultPKCE.getCodeVerifier());
        }
        return defaultPKCE;
    }

}
