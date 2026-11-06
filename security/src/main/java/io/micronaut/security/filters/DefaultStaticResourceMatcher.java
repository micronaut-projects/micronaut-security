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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.web.router.resource.StaticResourceResolver;
import jakarta.inject.Singleton;

/**
 * Resolves the request path with the server's {@link StaticResourceResolver}. The Netty runtime resolves static
 * resources from the decoded path and the servlet runtime from the raw path, so both are checked: a request is a
 * static resource when either form resolves, so that the filter rejects a superset of what either runtime serves.
 * This may turn a 404 of the active runtime into a 401 or 403 for percent-encoded paths.
 *
 * <p>This bean only exists when the router, which the HTTP server brings, is on the classpath, so that
 * {@link SecurityFilter} never names a router class and still loads without it.</p>
 *
 * @author Sergio del Amo
 * @since 4.18.2
 */
@Internal
@Requires(classes = { HttpRequest.class })
@Requires(beans = StaticResourceResolver.class)
@Requires(missingBeans = StaticResourceMatcher.class)
@Singleton
final class DefaultStaticResourceMatcher implements StaticResourceMatcher<HttpRequest<?>> {

    private final StaticResourceResolver staticResourceResolver;

    DefaultStaticResourceMatcher(StaticResourceResolver staticResourceResolver) {
        this.staticResourceResolver = staticResourceResolver;
    }

    @Override
    public boolean isStaticResource(@NonNull HttpRequest<?> request) {
        String rawPath = request.getPath();
        String decodedPath = request.getUri().getPath();
        if (decodedPath != null && staticResourceResolver.resolve(decodedPath).isPresent()) {
            return true;
        }
        return !rawPath.equals(decodedPath) && staticResourceResolver.resolve(rawPath).isPresent();
    }
}
