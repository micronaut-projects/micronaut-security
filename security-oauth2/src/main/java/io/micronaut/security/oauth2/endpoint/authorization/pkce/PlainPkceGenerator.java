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
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import java.util.List;

/**
 * Pkce generator for plain challenge method.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Named(PlainPkceGenerator.CODE_CHALLENGE_METHOD_PLAIN)
@Singleton
public class PlainPkceGenerator implements PkceGenerator {
    public static final Integer ORDER = S256PkceGenerator.ORDER + 100;
    public static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";

    private final CodeVerifierGenerator codeVerifierGenerator;

     /**
     *
     * @param codeVerifierGenerator Code Verifier generator
     */
    public PlainPkceGenerator(CodeVerifierGenerator codeVerifierGenerator) {

        this.codeVerifierGenerator = codeVerifierGenerator;
    }

    @Override
    public boolean supportsAny(List<String> codeChallengeMethods) {
        return codeChallengeMethods.stream().anyMatch(m -> m.equalsIgnoreCase(CODE_CHALLENGE_METHOD_PLAIN));
    }

    @Override
    @NonNull
    public Pkce generate() {
        String codeVerifier = codeVerifierGenerator.generate();
        return new Pkce(CODE_CHALLENGE_METHOD_PLAIN, codeVerifier, codeVerifier);
    }

    @Override
    @NonNull
    public String getName() {
        return PlainPkceGenerator.CODE_CHALLENGE_METHOD_PLAIN;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
