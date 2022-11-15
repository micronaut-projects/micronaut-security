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
import io.micronaut.core.annotation.ReflectiveAccess;

/**
 * Default PKCE implementation.
 *
 * @author Nemanja Mikic
 * @since 3.8.0
 */
@ReflectiveAccess
@Introspected
public final class DefaultPKCE implements PKCE {

    private String codeVerifier;
    private String codeMethod;
    private String codeChallenge;

    @NonNull
    @Override
    public String getCodeVerifier() {
        return codeVerifier;
    }

    public void setCodeVerifier(@NonNull String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    @NonNull
    @Override
    public String getCodeMethod() {
        return codeMethod;
    }

    public void setCodeMethod(String codeMethod) {
        this.codeMethod = codeMethod;
    }


    @NonNull
    @Override
    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }
}
