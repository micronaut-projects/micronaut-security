/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * CSRF Configuration.
 * @author Sergio del Amo
 * @since 4.11.0
 */
public interface CsrfConfiguration extends CookieConfiguration, Toggleable {
    String PREFIX = SecurityConfigurationProperties.PREFIX + ".csrf";

    /**
     *
     * @return Random value's size in bytes. The random value used is used to build a CSRF Token.
     */
    int getRandomValueSize();

    /**
     *
     * @return The Secret Key that is used to calculate an HMAC as part of a CSRF token generation.
     */
    @Nullable
    String getSecretKey();

    /**
     * HTTP Header name to look for the CSRF token. It is recommended to use a custom request header. By using a custom HTTP Header name, it will not be possible to send them cross-origin without a permissive CORS implementation.
     * @return HTTP Header name to look for the CSRF token.
     */
    @NonNull
    String getHeaderName();

    /**
     *
     * @return Key to look for the CSRF token in an HTTP Session.
     */
    @NonNull
    String getHttpSessionName();

    /**
     *
     * @return Field name in a form url encoded submission  to look for the CSRF token.
     */
    @NonNull
    String getFieldName();

    /**
     *
     * @return whether the CSRF cookie is a session cookie. A session cookie does not have an expiration date. If set to true, then {@link CsrfConfiguration#getCookieMaxAge()} is ignored.
     * @since 4.12.0
     */
    default boolean isSessionCookie() {
        return false;
    }
}
