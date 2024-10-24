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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.order.Ordered;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.session.Session;

/**
 * API that allows to populate the session after a successful login. You can create extra beans of type {@link SessionPopulator} to add extra data to the session.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> Request
 */
public interface SessionPopulator<T> extends Ordered {

    /**
     * Populates the session.
     * @param request  The request
     * @param authentication The authenticated user.
     * @param session The session
     */
    void populateSession(@NonNull T request,
                         @NonNull Authentication authentication,
                         @NonNull Session session);
}
