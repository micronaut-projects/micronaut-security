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

import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * {@link io.micronaut.context.annotation.DefaultImplementation} of {@link CodeVerifierGenerator} which generates a random code verifier using {@link PkceConfiguration#getEntropy()}.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Singleton
public class DefaultCodeVerifierGenerator implements CodeVerifierGenerator {

    private final PkceConfiguration pkceConfiguration;

    public DefaultCodeVerifierGenerator(PkceConfiguration pkceConfiguration) {
        this.pkceConfiguration = pkceConfiguration;
    }

    @Override
    @NonNull
    public String generate() {
        return generateRandomCodeVerifier();
    }

    /**
     * Generates a random code verifier string using {@link SecureRandom} as the source of
     * entropy, with the default entropy quantity as defined by {@link PkceConfiguration#getEntropy()}..
     *
     * @return String the generated code verifier
     */
    @NonNull
    private String generateRandomCodeVerifier() {
        return generateRandomCodeVerifier(new SecureRandom(), pkceConfiguration.getEntropy());
    }

    /**
     * Generates a random code verifier string using the provided entropy source and the specified
     * number of bytes of entropy.
     *
     * @param entropySource entropy source
     * @param entropyBytes  entropy bytes
     * @return String generated code verifier
     */
    @NonNull
    private String generateRandomCodeVerifier(SecureRandom entropySource, int entropyBytes) {
        byte[] randomBytes = new byte[entropyBytes];
        entropySource.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
