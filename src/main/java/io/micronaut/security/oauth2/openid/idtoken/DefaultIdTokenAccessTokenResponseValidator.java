/*
 * Copyright 2017-2018 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.idtoken;

import javax.inject.Singleton;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.openid.idtoken.validation.IdTokenClaimsValidator;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import org.reactivestreams.Publisher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;


/**
 * Default implementation of {@link IdTokenAccessTokenResponseValidator}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Requires(beans = {JwtTokenValidator.class})
@Singleton
public class DefaultIdTokenAccessTokenResponseValidator implements IdTokenAccessTokenResponseValidator {

    private final JwtTokenValidator jwtTokenValidator;
    private final List<JwtClaimsValidator> jwtClaimsValidator;

    /**
     *
     * @param jwtTokenValidator JWT token Validator
     */
    public DefaultIdTokenAccessTokenResponseValidator(JwtTokenValidator jwtTokenValidator,
                                                      Collection<GenericJwtClaimsValidator> genericValidators,
                                                      Collection<IdTokenClaimsValidator> idTokenValidators) {
        this.jwtTokenValidator = jwtTokenValidator;
        jwtClaimsValidator = new ArrayList<>();
        jwtClaimsValidator.addAll(genericValidators);
        jwtClaimsValidator.addAll(idTokenValidators);
    }

    @Override
    public Optional<Authentication> validate(IdTokenAccessTokenResponse idTokenAccessTokenResponse) {
        return jwtTokenValidator.authenticationIfValidJwtSignatureAndClaims(idTokenAccessTokenResponse.getIdToken(),
                getJwtClaimsValidator());
    }

    public List<JwtClaimsValidator> getJwtClaimsValidator() {
        return jwtClaimsValidator;
    }
}
