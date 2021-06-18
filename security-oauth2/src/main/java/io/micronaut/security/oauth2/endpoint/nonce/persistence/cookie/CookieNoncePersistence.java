/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence;

import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Nonce persistence with a cookie.
 *
 * @author James Kleeh
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Requires(property = DefaultNonceConfiguration.PREFIX + ".persistence", value = DefaultNonceConfiguration.PERSISTENCE_COOKIE, defaultValue = DefaultNonceConfiguration.DEFAULT_PERSISTENCE)
@Singleton
public class CookieNoncePersistence implements NoncePersistence {

    private final CookieNoncePersistenceConfiguration configuration;

    /**
     * @param configuration The cookie configuration
     */
    public CookieNoncePersistence(CookieNoncePersistenceConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Optional<String> retrieveNonce(HttpRequest<?> request) {
        Cookie cookie = request.getCookies().get(configuration.getCookieName());
        return Optional.ofNullable(cookie)
                .map(Cookie::getValue);
    }

    @Override
    public void persistNonce(HttpRequest<?> request, MutableHttpResponse response, String nonce) {
        Cookie cookie = Cookie.of(configuration.getCookieName(), nonce);
        cookie.configure(configuration, request.isSecure());
        response.cookie(cookie);
    }
}
