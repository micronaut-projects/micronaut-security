/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.ClaimPasetoException;
import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.PasetoParser;
import dev.paseto.jpaseto.Pasetos;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @author Utsav Varia
 * @since 3.0
 */
public class PasetoValidator {

    private static final Logger LOG = LoggerFactory.getLogger(PasetoValidator.class);

    /**
     * Validates the supplied token with any configurations and claim validators present.
     * @param token The Paseto string
     * @param request HTTP request
     * @return An optional Paseto token if validation succeeds
     */
    public Optional<Paseto> validate(String token, @Nullable HttpRequest<?> request) {
        try {
            PasetoParser builder = Pasetos.parserBuilder().build();
            Paseto paseto = builder.parse(token);
            return Optional.of(paseto);
        } catch (ClaimPasetoException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Failed to parse Paseto token: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
}
