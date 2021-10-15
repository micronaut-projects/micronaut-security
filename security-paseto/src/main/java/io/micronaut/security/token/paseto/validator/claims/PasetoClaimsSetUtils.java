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

import io.micronaut.security.token.paseto.generator.claims.PasetoClaims;
import io.micronaut.security.token.paseto.generator.claims.PasetoClaimsSet;

/**
 * @author Utsav Varia
 * @since 3.0
 */
public final class PasetoClaimsSetUtils {

    private PasetoClaimsSetUtils() {
    }

    /**
     * @param claims Paseto claims
     * @return A PasetoClaimsSet
     */
    public static PasetoClaimsSet pasetoClaimsSetFromClaims(PasetoClaims claims) {
        PasetoClaimsSet.Builder claimsSetBuilder = new PasetoClaimsSet.Builder();
        for (String k : claims.names()) {
            claimsSetBuilder.claim(k, claims.get(k));
        }
        return claimsSetBuilder.build();
    }

}
