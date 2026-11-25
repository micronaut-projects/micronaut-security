/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.PasetoParser;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;

/**
 * {@link Factory} to create multiple {@link PasetoTokenValidator} for beans of type {@link PasetoParser}.
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Factory
public class PasetoTokenValidatorFactory {
    private final PasetoAuthenticationFactory pasetoAuthenticationFactory;

    public PasetoTokenValidatorFactory(PasetoAuthenticationFactory pasetoAuthenticationFactory) {
        this.pasetoAuthenticationFactory = pasetoAuthenticationFactory;
    }

    /**
     *
     * @param pasetoParser Paseto Parser
     * @return A PastetoTokenValidator
     */
    @EachBean(PasetoParser.class)
    @Singleton
    PasetoTokenValidator createPasetoTokenValidator(PasetoParser pasetoParser) {
        return new PasetoTokenValidator(pasetoAuthenticationFactory, pasetoParser);
    }
}
