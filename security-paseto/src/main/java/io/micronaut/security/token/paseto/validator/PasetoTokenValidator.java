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

import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.PasetoException;
import dev.paseto.jpaseto.PasetoParser;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import java.util.Optional;

/**
 * {@link TokenValidator} for Paseto tokens.
 * @author Utsav Varia
 * @since 3.0
 */
public class PasetoTokenValidator implements TokenValidator<HttpRequest<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(PasetoTokenValidator.class);
    protected PasetoAuthenticationFactory pasetoAuthenticationFactory;
    protected PasetoParser pasetoParser;

    public PasetoTokenValidator(PasetoAuthenticationFactory pasetoAuthenticationFactory,
                                PasetoParser pasetoParser) {
        this.pasetoAuthenticationFactory = pasetoAuthenticationFactory;
        this.pasetoParser = pasetoParser;
    }

    @Override
    public Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
        return parse(token)
                .flatMap(pasetoAuthenticationFactory::createAuthentication)
                .map(Mono::just)
                .orElse(Mono.empty());
    }

    /**
     * Validates the supplied token with any configurations and claim validators present.
     *
     * @param token The Paseto string
     * @return An optional Paseto token if validation succeeds
     */
    private Optional<Paseto> parse(String token) {
        try {
            return Optional.of(pasetoParser.parse(token));
        } catch (PasetoException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Failed to parse Paseto token: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
}
