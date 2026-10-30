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
package io.micronaut.security.event;

import io.micronaut.context.event.ApplicationEvent;

/**
 * Event triggered when the user logs out.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class LogoutEvent extends ApplicationEvent {

    /**
     * Event triggered when the user logs out.
     *
     * @param source The {@link io.micronaut.security.authentication.Authentication} of the user logging out.
     * @throws IllegalArgumentException if source is null.
     */
    public LogoutEvent(Object source) {
        super(source);
    }

    /**
     * The string representation never includes the source. Micronaut logs every published
     * event at DEBUG using its string representation, and the source may carry tokens or an
     * authentication with sensitive attributes.
     *
     * @return The string representation of the event with the source redacted.
     * @since 3.11.3
     */
    @Override
    public String toString() {
        return getClass().getName() + "[source=<redacted>]";
    }
}
