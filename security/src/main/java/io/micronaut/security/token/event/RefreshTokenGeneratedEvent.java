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
package io.micronaut.security.token.event;

import io.micronaut.context.event.ApplicationEvent;
import io.micronaut.security.authentication.UserDetails;

/**
 * Triggered when a JWT refresh token is generated.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class RefreshTokenGeneratedEvent extends ApplicationEvent {

    private final UserDetails userDetails;
    private final String refreshToken;

    /**
     * Triggered when a refresh token is generated.
     *
     * @param source A String with the JWT refresh token generated.
     * @throws IllegalArgumentException if source is null.
     * @deprecated Use {@link #RefreshTokenGeneratedEvent(UserDetails, String)} instead
     */
    @Deprecated
    public RefreshTokenGeneratedEvent(Object source) {
        super(source);
        this.userDetails = null;
        this.refreshToken = source.toString();
    }

    /**
     * Triggered when a refresh token is generated.
     *
     * @param userDetails The user details
     * @param refreshToken The refresh token
     * @throws IllegalArgumentException if source is null.
     */
    public RefreshTokenGeneratedEvent(UserDetails userDetails, String refreshToken) {
        super(refreshToken);
        this.userDetails = userDetails;
        this.refreshToken = refreshToken;
    }

    /**
     * @return The user details
     */
    public UserDetails getUserDetails() {
        return userDetails;
    }

    /**
     * @return The refresh token
     */
    public String getRefreshToken() {
        return refreshToken;
    }
}
