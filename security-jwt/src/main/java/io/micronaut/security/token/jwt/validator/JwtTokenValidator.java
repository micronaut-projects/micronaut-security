/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWT;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens">Validating JWT Access Tokens</a>
 *
 * @author Sergio del Amo
 * @since 1.0
 * @param <T> Request
 */
@Singleton
public class JwtTokenValidator<T> implements TokenValidator<T> {
    private final JwtAuthenticationFactory jwtAuthenticationFactory;
    private final JsonWebTokenValidator<JWT, T> validator;



    public JwtTokenValidator(JwtAuthenticationFactory jwtAuthenticationFactory, JsonWebTokenValidator<JWT, T> validator) {
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
        this.validator = validator;
    }

    @Override
    public Optional<Authentication> validateToken(String token, T request) {
        return validator.validate(token, request)
                .flatMap(jwtAuthenticationFactory::createAuthentication);
    }
}
