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
package io.micronaut.security.session;


import io.micronaut.core.annotation.Indexed;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.order.Ordered;
import io.micronaut.data.annotation.Index;
import io.micronaut.security.config.SecurityConfigurationProperties;

import java.util.Optional;

/**
 * API to resolve a session id for a given request. A session ID could be an HTTP Session ID but also a JSON Web Token Identifier in a token based state-less authentication.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T>  Request
 */
@Indexed(SessionIdResolver.class)
public interface SessionIdResolver<T> extends Ordered {
    /**
     * Prefix used in SessionID resolver implementation.s.
     */
    String PREFIX = SecurityConfigurationProperties.PREFIX  + ".sessionid-resolver";

    /**
     *
     * @param request Request
     * @return Session ID for the given request. Empty if no session ID was found.
     */
    @NonNull
    Optional<String> findSessionId(@NonNull T request);
}
