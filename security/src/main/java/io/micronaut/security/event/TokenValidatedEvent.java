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

import java.util.Locale;

/**
 * Triggered when a token is validated.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class TokenValidatedEvent extends SecurityEvent {

    /**
     * Triggered when a token is validated.
     *
     * @param source A String containing the token being validated.
     * @param host The hostname from the request if available
     * @param locale The locale of the request
     * @throws IllegalArgumentException if source is null.
     * @since 4.7.0
     */
    public TokenValidatedEvent(
        Object source,
        String host,
        Locale locale
    ) {
        super(source, host, locale);
    }
}
