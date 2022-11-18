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
package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.Pkce;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Persists the Proof of Key Exchange (PKCE) code_verifier value in a cookie.
 *
 * @author Nemanja Mikic
 * @since 3.9.0
 */
@Singleton
public class CookiePkcePersistence implements PkcePersistence {

    private final CookiePkcePersistenceConfiguration configuration;

    /**
     * @param configuration The cookie configuration
     */
    public CookiePkcePersistence(CookiePkcePersistenceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Retrieve the code verifier and removes it from the session if present.
     *
     * @param request The request
     * @return The optional PKCE code verifier
     */
    @Override
    @NonNull
    public Optional<String> retrieveCodeVerifier(@NonNull HttpRequest<?> request) {
        Cookie cookie = request.getCookies().get(configuration.getCookieName());
        return Optional.ofNullable(cookie)
            .map(Cookie::getValue);
    }

    @Override
    public void persistPkce(@NonNull HttpRequest<?> request,
                            @NonNull MutableHttpResponse<?> response,
                            @NonNull Pkce pkce) {
        Cookie cookie = Cookie.of(configuration.getCookieName(), pkce.getCodeVerifier());
        cookie.configure(configuration, request.isSecure());
        response.cookie(cookie);
    }
}
