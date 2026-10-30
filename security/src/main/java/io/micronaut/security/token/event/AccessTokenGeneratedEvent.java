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

/**
 * Triggered when a JWT access token is generated.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class AccessTokenGeneratedEvent extends ApplicationEvent {

    /**
     * Triggered when a JWT access token is generated.
     *
     * @param source A String with the JWT access token generated.
     * @throws IllegalArgumentException if source is null.
     */
    public AccessTokenGeneratedEvent(Object source) {
        super(source);
    }

    /**
     * The string representation never includes the access token. Micronaut logs every published
     * event at DEBUG using its string representation, so exposing it would write the access token to the log.
     *
     * @return The string representation of the event with the access token redacted.
     * @since 4.18.2
     */
    @Override
    public String toString() {
        return getClass().getName() + "[source=<redacted>]";
    }
}
