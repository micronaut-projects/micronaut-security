/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.core.annotation.NonNull;

/**
 * Resolves the name token based authentication gives to a user on later requests from the {@link Authentication}
 * a token is issued for, the way {@link AbstractTokenAuthenticationFactory} resolves it from the claims of the token:
 * the {@link TokenConfiguration#getNameKey()} claim, falling back to the {@code sub} claim, which is the principal name.
 * @author Sergio del Amo
 * @since 4.18.2
 */
@Internal
public final class TokenAuthenticationNames {

    private TokenAuthenticationNames() {
    }

    /**
     * @param tokenConfiguration Token Configuration
     * @param authentication The authentication a token is issued for
     * @return The authentication named as token based authentication names the user from the issued token, or the
     * supplied authentication if the name is the same
     */
    @NonNull
    public static Authentication asResolvedFromToken(@NonNull TokenConfiguration tokenConfiguration,
                                                     @NonNull Authentication authentication) {
        String nameKey = tokenConfiguration.getNameKey();
        if (TokenConfiguration.DEFAULT_NAME_KEY.equals(nameKey)) {
            return authentication;
        }
        Object fromClaim = authentication.getAttributes().get(nameKey);
        if (fromClaim == null) {
            return authentication;
        }
        String name = fromClaim.toString();
        if (name.equals(authentication.getName())) {
            return authentication;
        }
        return Authentication.build(name, authentication.getRoles(), authentication.getAttributes());
    }
}
