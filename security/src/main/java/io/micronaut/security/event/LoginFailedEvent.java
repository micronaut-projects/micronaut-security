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
package io.micronaut.security.event;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.UsernamePasswordCredentials;

import java.util.Locale;

/**
 * Event triggered when an unsuccessful login takes place.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class LoginFailedEvent extends SecurityEvent {

    @Nullable
    private final AuthenticationRequest authenticationRequest;

    /**
     * Event triggered when an unsuccessful login takes place.
     *
     * @param source                The {@link io.micronaut.security.authentication.AuthenticationResponse} object
     *                              signaling the authentication failure and reason.
     * @param authenticationRequest A request to authenticate.
     * @param host                  The hostname from the request if available
     * @param locale                The locale of the request
     * @throws IllegalArgumentException if source is null.
     * @since 4.7.0
     */
    public LoginFailedEvent(
        Object source,
        AuthenticationRequest authenticationRequest,
        @Nullable String host,
        Locale locale
    ) {
        super(source, host, locale);
        this.authenticationRequest = authenticationRequest;
    }

    /**
     * Event triggered when an unsuccessful login takes place.
     *
     * @param source                The {@link io.micronaut.security.authentication.AuthenticationResponse} object
     *                              signaling the authentication failure and reason.
     * @param authenticationRequest A request to authenticate.
     * @throws IllegalArgumentException if source is null.
     * @since 4.1.0
     * @deprecated use {@link LoginFailedEvent(Object, AuthenticationRequest, String, Locale)}.
     */
    @Deprecated(forRemoval = true, since = "4.7.0")
    public LoginFailedEvent(Object source, AuthenticationRequest authenticationRequest) {
        this(source, authenticationRequest, null, Locale.getDefault());
    }

    /**
     * Event triggered when an unsuccessful login takes place.
     *
     * @param source The {@link io.micronaut.security.authentication.AuthenticationResponse} object
     *               signaling the authentication failure and reason.
     * @throws IllegalArgumentException if source is null.
     * @deprecated use {@link LoginFailedEvent(Object, UsernamePasswordCredentials)}.
     */
    @Deprecated(forRemoval = true, since = "4.1.0")
    public LoginFailedEvent(Object source) {
        this(source, null, null, Locale.getDefault());
    }

    /**
     * @return A request to authenticate.
     * @since 4.1.0
     */
    @Nullable
    public AuthenticationRequest getAuthenticationRequest() {
        return authenticationRequest;
    }
}
