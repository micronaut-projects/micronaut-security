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
package io.micronaut.security.token.jwt.validator;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Configuration to enable or disable beans of type {@link JwtClaimsValidator}.
 *
 * @author Sergio del Amo
 * @since 2.4.0
 */
public interface JwtClaimsValidatorConfiguration {

    /**
     *
     * @return Whether the aud claim should be validated to ensure it matches this value.
     */
    @Nullable
    String getAudience();

    /**
     *
     * @return Whether the iss claim should be validated to ensure it matches this value.
     */
    @Nullable
    String getIssuer();

    /**
     *
     * @return Whether the JWT subject claim should be validated to ensure it is not null.
     */
    boolean isSubjectNotNull();

    /**
     *
     * @return Whether it should be validated that validation time is not before the not-before claim (nbf) of a JWT token.
     */
    boolean isNotBefore();

    /**
     *
     * @return Whether the expiration date of the JWT should be validated.
     */
    boolean isExpiration();

    /**
     *
     * @return Whether the nonce claim should be validated when a nonce was present.
     */
    boolean isNonce();

    /**
     * @return Whether `IdTokenClaimsValidator`, which performs some fo the verifications described in OpenID Connect Spec, is enabled. Only applies for `idtoken` authentication mode.
     */
    boolean isOpenidIdtoken();
}


