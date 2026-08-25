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
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.rules.ConfigurationInterceptUrlMapRule;
import io.micronaut.web.router.RouteAttributes;
import io.micronaut.web.router.RouteMatch;
import io.micronaut.web.router.resource.StaticResourceResolver;
import jakarta.inject.Singleton;

/**
 * Default static-resource-based implementation of {@link StaticResourceAuthenticationBypass}.
 */
@Internal
@Requires(classes = { HttpRequest.class, StaticResourceResolver.class })
@Requires(beans = { ConfigurationInterceptUrlMapRule.class, StaticResourceResolver.class })
@Requires(missingBeans = StaticResourceAuthenticationBypass.class)
@Singleton
final class DefaultStaticResourceAuthenticationBypass implements StaticResourceAuthenticationBypass<HttpRequest<?>> {

    private final StaticResourceResolver staticResourceResolver;
    private final ConfigurationInterceptUrlMapRule interceptUrlMapRule;

    DefaultStaticResourceAuthenticationBypass(StaticResourceResolver staticResourceResolver,
                                              ConfigurationInterceptUrlMapRule interceptUrlMapRule) {
        this.staticResourceResolver = staticResourceResolver;
        this.interceptUrlMapRule = interceptUrlMapRule;
    }

    /**
     * A route always takes precedence over a static resource. For an unmatched GET request,
     * resolve the resource before consulting the intercept URL map.
     *
     * @param request The current request
     * @return Whether authentication resolution can be skipped
     */
    @Override
    public boolean shouldBypass(HttpRequest<?> request) {
        if (!(request.getMethod() == HttpMethod.GET || request.getMethod() == HttpMethod.HEAD)) {
            return false;
        }
        try (RouteMatch<?> routeMatch = RouteAttributes.getRouteMatch(request).orElse(null)) {
            if (routeMatch != null) {
                return false;
            }
        }
        return staticResourceResolver.resolve(request.getUri().getPath()).isPresent()
            && interceptUrlMapRule.isAnonymous(request);
    }
}
