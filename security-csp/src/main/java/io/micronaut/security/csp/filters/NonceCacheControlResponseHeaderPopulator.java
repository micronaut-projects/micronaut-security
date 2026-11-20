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
package io.micronaut.security.csp.filters;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.server.RouteExecutor;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.web.router.RouteAttributes;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * {@link ResponseHeaderPopulator} that adds the configured {@code Cache-Control} header to HTML and
 * XHTML responses of requests that received a Content Security Policy nonce. A shared cache that
 * stored such a response would replay the same nonce to every visitor.
 *
 * <p>Other content types cannot carry the nonce in their body and keep their caching. A
 * {@code Cache-Control} header already set by the application is kept. The populator is only loaded
 * when {@value ContentSecurityPolicyFilterConfigurationProperties#PROPERTY_NONCE_CACHE_CONTROL} is
 * set and an enabled directive uses nonces.</p>
 *
 * @since 5.6.0
 */
@Requires(classes = ResponseHeaderPopulator.class)
@Requires(property = ContentSecurityPolicyFilterConfigurationProperties.PROPERTY_NONCE_CACHE_CONTROL)
@Requires(condition = NonceEnabledCondition.class)
@Singleton
@Internal
final class NonceCacheControlResponseHeaderPopulator implements ResponseHeaderPopulator {
    private final @Nullable List<HttpHeaderEntry> cacheControl;
    private final RouteExecutor routeExecutor;

    /**
     * Creates the populator.
     *
     * @param cspFilterConfiguration configures the {@code Cache-Control} value to write
     * @param routeExecutor resolves the content type of a response that does not declare one yet
     */
    NonceCacheControlResponseHeaderPopulator(ContentSecurityPolicyFilterConfiguration cspFilterConfiguration,
                                             RouteExecutor routeExecutor) {
        this.routeExecutor = routeExecutor;
        String value = cspFilterConfiguration.getNonceCacheControl();
        this.cacheControl = StringUtils.hasText(value) ? List.of(new HttpHeaderEntry(HttpHeaders.CACHE_CONTROL, value)) : null;
    }

    @Override
    public @Nullable Collection<HttpHeaderEntry> findHttpHeaders(HttpRequest<?> request, HttpResponse<?> response) {
        if (cacheControl == null
            || request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isEmpty()
            || !contentType(request, response).filter(NonceCacheControlResponseHeaderPopulator::canCarryNonce).isPresent()) {
            return null;
        }
        return cacheControl;
    }

    /**
     * Returns the content type of the response. A response filter runs before the server writes the
     * content type declared by the route, so when the response has none yet it is resolved from the
     * route the way the server will resolve it.
     *
     * @param request the current request
     * @param response the current response
     * @return the content type the response will be sent with, if it can be told
     */
    private Optional<MediaType> contentType(HttpRequest<?> request, HttpResponse<?> response) {
        return response.getContentType()
            .or(() -> RouteAttributes.getRouteInfo(request)
                .map(routeInfo -> routeExecutor.resolveDefaultResponseContentType(request, routeInfo)));
    }

    private static boolean canCarryNonce(MediaType mediaType) {
        String name = mediaType.getName();
        return MediaType.TEXT_HTML.equalsIgnoreCase(name) || MediaType.APPLICATION_XHTML.equalsIgnoreCase(name);
    }
}
