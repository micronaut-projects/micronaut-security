/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;

/**
 * Proof Key for Code Exchange.
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</a>
 */
@Introspected
public class Pkce implements PkceChallenge {

    @NonNull
    private final String codeChallengeMethod;

    @NonNull
    private final String codeChallenge;

    @NonNull
    private final String codeVerifier;

    public Pkce(@NonNull String codeChallengeMethod,
                @NonNull String codeChallenge,
                @NonNull String codeVerifier) {
        this.codeVerifier = codeVerifier;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
    }

    @Override
    @NonNull
    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    @Override
    @NonNull
    public String getCodeChallenge() {
        return codeChallenge;
    }

    /**
     *
     * @return A cryptographically random string that is used to correlate the authorization request to the token request.
     */
    @NonNull
    public String getCodeVerifier() {
        return codeVerifier;
    }
}
