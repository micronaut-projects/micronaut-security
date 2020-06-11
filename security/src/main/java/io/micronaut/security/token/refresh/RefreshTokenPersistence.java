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
package io.micronaut.security.token.refresh;

import io.micronaut.runtime.event.annotation.EventListener;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import org.reactivestreams.Publisher;

/**
 * Responsible for persisting refresh tokens and retrieving
 * user details by a refresh token.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
public interface RefreshTokenPersistence {

    /**
     * Persist the refresh token.
     *
     * @param event The refresh token generated event
     */
    @EventListener
    void persistToken(RefreshTokenGeneratedEvent event);

    /**
     * @param refreshToken The refresh token
     * @return The user details associated with the refresh token
     */
    Publisher<Authentication> getAuthentication(String refreshToken);

}
