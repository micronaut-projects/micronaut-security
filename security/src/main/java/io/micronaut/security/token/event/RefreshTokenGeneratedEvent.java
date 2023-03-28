/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.security.authentication.Authentication;

/**
 * Triggered when a JWT refresh token is generated.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class RefreshTokenGeneratedEvent extends ApplicationEvent {

    private final Authentication authentication;
    private final String refreshToken;

    /**
     * Triggered when a refresh token is generated.
     *
     * @param authentication The user details
     * @param refreshToken The refresh token
     * @throws IllegalArgumentException if source is null.
     */
    public RefreshTokenGeneratedEvent(Authentication authentication, String refreshToken) {
        super(refreshToken);
        this.authentication = authentication;
        this.refreshToken = refreshToken;
    }

    /**
     * @return The user details
     */
    public Authentication getAuthentication() {
        return authentication;
    }

    /**
     * @return The refresh token
     */
    public String getRefreshToken() {
        return refreshToken;
    }
}
