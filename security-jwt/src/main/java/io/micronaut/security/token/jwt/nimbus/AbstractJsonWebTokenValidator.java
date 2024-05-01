/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;


/**
 * Abstract class for common methods for JWT validation.
 * @param <R> Request
 * @since 4.8.0
 */
abstract class AbstractJsonWebTokenValidator<R> {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractJsonWebTokenValidator.class);

    private final boolean noSignatures;
    private List<? extends JwtClaimsValidator<R>> claimsValidators;

    AbstractJsonWebTokenValidator(List<GenericJwtClaimsValidator<R>> claimsValidators,
                                  List<SignatureConfiguration> imperativeSignatureConfigurations,
                                  List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations) {
        this.claimsValidators = claimsValidators;
        this.noSignatures = imperativeSignatureConfigurations.isEmpty() && reactiveSignatureConfigurations.isEmpty();
    }

    protected boolean validateSignature(PlainJWT plainJWT) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating plain JWT");
        }
        if (noSignatures) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT is not signed and no signature configurations -> verified");
            }
            return true;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A non-signed JWT cannot be accepted as signature configurations have been defined");
            }
            return false;
        }
    }

    protected boolean validateClaims(JWT jwt, R request) {
        if (claimsValidators.isEmpty()) {
            return true;
        }
        try {
            Claims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
            if (claimsValidators.stream().allMatch(validator -> validator.validate(claims, request))) {
                return true;
            }
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to retrieve the claims set", e);
            }
        }
        return false;
    }
}
