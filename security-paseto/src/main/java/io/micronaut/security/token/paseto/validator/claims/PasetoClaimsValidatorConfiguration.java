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
package io.micronaut.security.token.paseto.validator.claims;

import io.micronaut.core.annotation.Nullable;

/**
 * @author Utsav Varia
 * @since 3.0
 */
public interface PasetoClaimsValidatorConfiguration {

    /**
     * @return Whether the aud claim should be validated to ensure it matches this value.
     */
    @Nullable
    String getAudience();

    /**
     * @return Whether the iss claim should be validated to ensure it matches this value.
     */
    @Nullable
    String getIssuer();

    /**
     * @return Whether the Paseto subject claim should be validated to ensure it is not null.
     */
    boolean isSubjectNotNull();

    /**
     * @return Whether it should be validated that validation time is not before the not-before claim (nbf) of a Paseto token.
     */
    boolean isNotBefore();

    /**
     * @return Whether the expiration date of the Paseto should be validated.
     */
    boolean isExpiration();

}
