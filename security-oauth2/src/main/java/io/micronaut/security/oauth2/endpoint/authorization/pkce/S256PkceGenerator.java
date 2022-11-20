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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * SHA-256 based PKCE Generator.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7636#section-4.3">xProof Key for Code Exchange by OAuth Public Clients (RFC 7636), Section 4.3</a>
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Named(S256PkceGenerator.CODE_CHALLENGE_METHOD_S256)
@Singleton
@Requires(condition = Sha256Condition.class)
public class S256PkceGenerator implements PkceGenerator {
    public static final Integer ORDER = 0;

    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    private final CodeVerifierGenerator codeVerifierGenerator;

    /**
     *
     * @param codeVerifierGenerator Code Verifier generator
     */
    public S256PkceGenerator(CodeVerifierGenerator codeVerifierGenerator) {
        this.codeVerifierGenerator = codeVerifierGenerator;
    }

    @Override
    @NonNull
    public String getName() {
        return S256PkceGenerator.CODE_CHALLENGE_METHOD_S256;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public boolean supportsAny(@NonNull List<String> codeChallengeMethods) {
        return codeChallengeMethods.stream().anyMatch(m -> m.equalsIgnoreCase(CODE_CHALLENGE_METHOD_S256));
    }

    @Override
    @NonNull
    public Pkce generate() {
        String codeVerifier = codeVerifierGenerator.generate();
        return new Pkce(CODE_CHALLENGE_METHOD_S256, hash(codeVerifier), codeVerifier);
    }

    /**
     *
     * @param value Value to be hashed
     * @return a hash build with algorithm SHA-256
     */
    @NonNull
    public static String hash(@NonNull String value) {
        try {
            MessageDigest sha256Digester = MessageDigest.getInstance("SHA-256");
            sha256Digester.update(value.getBytes(StandardCharsets.ISO_8859_1));
            byte[] digestBytes = sha256Digester.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digestBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new ConfigurationException("SHA-256 is not supported on this device!. This should bean should not have been loaded");
        }
    }
}
