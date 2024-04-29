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
package io.micronaut.security.token.jwt.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.Claims;

/**
 * Signature Generator configuration.
 *
 * @author Sergio del Amo
 * @since 1.0
 * @param <T> Signed JWT
 * @param <A> signature Algorithm
 */
public interface SignatureGeneratorConfiguration<T, A> extends SignatureConfiguration<T, A> {

    /**
     * Generate a signed JWT based on claims.
     * @throws Exception could be thrown while signing the JWT token
     * @param claims the provided claims
     * @return the signed JWT
     */
    SignedJWT sign(Claims claims) throws Exception;
}

