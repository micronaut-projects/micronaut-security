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

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class PasetoTokenValidator implements TokenValidator {

    protected PasetoAuthenticationFactory pasetoAuthenticationFactory;
    protected PasetoValidator validator;

    public PasetoTokenValidator(PasetoAuthenticationFactory pasetoAuthenticationFactory, PasetoValidator validator) {
        this.pasetoAuthenticationFactory = pasetoAuthenticationFactory;
        this.validator = validator;
    }

    @Override
    public Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
        return validator.validate(token, request)
                .flatMap(pasetoAuthenticationFactory::createAuthentication)
                .map(Flux::just)
                .orElse(Flux.empty());
    }
}
