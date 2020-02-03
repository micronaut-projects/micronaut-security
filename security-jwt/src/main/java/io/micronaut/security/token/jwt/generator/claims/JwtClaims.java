/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.generator.claims;

import io.micronaut.security.token.Claims;

import java.util.Arrays;
import java.util.List;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1">Registered Claims Names</a>
 */
public interface JwtClaims extends Claims {
    String ISSUER          = "iss";

    String SUBJECT         = "sub";

    String EXPIRATION_TIME = "exp";

    String NOT_BEFORE      = "nbf";

    String ISSUED_AT       = "iat";

    String JWT_ID          = "jti";

    String AUDIENCE        = "aud";

    List<String> ALL_CLAIMS = Arrays.asList(ISSUER, SUBJECT, EXPIRATION_TIME, NOT_BEFORE, ISSUED_AT, JWT_ID, AUDIENCE);

}
