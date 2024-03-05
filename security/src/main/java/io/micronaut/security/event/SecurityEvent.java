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

import io.micronaut.context.event.ApplicationEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Nullable;

import java.util.Locale;
import java.util.Optional;

/**
 * Base class for security events.
 *
 * @author Tim Yates
 * @since 4.7.0
 */
@Internal
public abstract class SecurityEvent extends ApplicationEvent {

    private final transient String host;
    private final transient Locale locale;

    /**
     * @param source The source of the event
     * @param host   The hostname from the request if available
     * @param locale The locale of the request
     */
    protected SecurityEvent(Object source, @Nullable String host, Locale locale) {
        super(source);
        this.host = host;
        this.locale = locale;
    }

    /**
     * @return The hostname from the request if available
     */
    public Optional<String> getHost() {
        return Optional.ofNullable(host);
    }

    /**
     * @return The locale of the request
     */
    public Locale getLocale() {
        return locale;
    }
}
