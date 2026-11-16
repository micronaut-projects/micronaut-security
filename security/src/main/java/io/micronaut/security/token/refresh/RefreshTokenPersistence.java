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
     * <p>This method is an {@link EventListener} and it is invoked <strong>synchronously</strong>, on the
     * thread that completed authentication, while the login (or token refresh) response is being built.
     * When the authentication is emitted by a reactive authentication provider (or by an OAuth 2.0 / OpenID
     * Connect flow), that thread is typically a Netty event loop thread.</p>
     *
     * <p>Implementations which perform blocking I/O (for example, a JDBC or JPA write) must not block the
     * event loop. Offload the work by annotating the implementing method with
     * {@code @io.micronaut.scheduling.annotation.Async(TaskExecutors.BLOCKING)}, which executes the method on
     * the blocking executor and returns immediately. Note that {@code @ExecuteOn} has no effect on event
     * listener methods. When offloaded, the login response may be sent before the refresh token is
     * persisted.</p>
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
