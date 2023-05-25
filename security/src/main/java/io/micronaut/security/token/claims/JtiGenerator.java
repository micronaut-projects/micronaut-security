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
package io.micronaut.security.token.claims;

/**
 * Generates the "jti" (Token ID) claim, which provides a unique identifier for the token.
 * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1">4.1.7. "jti" (JWT ID) Claim</a> for JWT tokens.
 * @author Sergio del Amo
 * @version 1.0
 */
public interface JtiGenerator {

    /**
     *
     * @return a case-sensitive String which is used as a unique identifier for the JWT.
     */
    String generateJtiClaim();
}
