/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.filters;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;

/**
 * Decides whether the server could serve a request that matches no route as a
 * <a href="https://docs.micronaut.io/latest/guide/#staticResources">static resource</a>.
 *
 * <p>{@link SecurityFilter} consults it for a request that no security rule decides and that matches no route, so
 * that a static resource no rule covers is rejected instead of being served when
 * {@code micronaut.security.reject-not-found} is disabled. The default implementation resolves the request path the
 * way the server does, and only exists when the server's static resource resolver is available. Provide a bean of
 * this type to replace it.</p>
 *
 * @param <T> The request type
 * @author Sergio del Amo
 * @since 5.5.2
 */
@FunctionalInterface
@Internal
interface StaticResourceMatcher<T> {

    /**
     * @param request The request, which matches no route
     * @return Whether the server could serve the request as a static resource
     */
    boolean isStaticResource(@NonNull T request);
}
