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
package io.micronaut.security.oauth2.url;

import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.web.router.exceptions.RoutingException;
import jakarta.inject.Singleton;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OauthRouteUrlBuilder}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = HttpHostResolver.class)
@Singleton
public class DefaultOauthRouteUrlBuilder implements OauthRouteUrlBuilder<HttpRequest<?>> {

    private static final String HTTP = "http";
    private final HttpHostResolver hostResolver;
    private final String loginUriTemplate;
    private final String callbackUriTemplate;
    @Nullable
    private final String baseUrl;

    /**
     * @param hostResolver The host resolver
     * @param oauthConfiguration The oauth configuration
     */
    DefaultOauthRouteUrlBuilder(HttpHostResolver hostResolver,
                                OauthConfiguration oauthConfiguration) {
        this.hostResolver = hostResolver;
        this.loginUriTemplate = oauthConfiguration.getLoginUri();
        this.callbackUriTemplate = oauthConfiguration.getCallbackUri();
        this.baseUrl = oauthConfiguration.getBaseUrl().orElse(null);
    }

    @Override
    public URL buildLoginUrl(@Nullable HttpRequest<?> originating, String providerName) {
        return build(originating, providerName, loginUriTemplate);
    }

    @Override
    public URL buildCallbackUrl(@Nullable HttpRequest<?> originating, String providerName) {
        return build(originating, providerName, callbackUriTemplate);
    }

    @Override
    public URI buildLoginUri(@Nullable String providerName) {
        try {
            return new URI(getPath(loginUriTemplate, providerName));
        } catch (URISyntaxException e) {
            throw new RoutingException("Error building a URI for the path [" + loginUriTemplate + "]", e);
        }
    }

    @Override
    public URI buildCallbackUri(@Nullable String providerName) {
        try {
            return new URI(getPath(callbackUriTemplate, providerName));
        } catch (URISyntaxException e) {
            throw new RoutingException("Error building a URI for the path [" + callbackUriTemplate + "]", e);
        }
    }

    /**
     * Builds a URL with the provided arguments.
     *
     * @param originating The originating request
     * @param providerName The oauth provider name
     * @param uriTemplate The URI template
     * @return The URL
     */
    protected URL build(@Nullable HttpRequest<?> originating, String providerName, String uriTemplate) {
        return buildUrl(originating, getPath(uriTemplate, providerName));
    }

    /**
     * Builds the path portion of the URL.
     *
     * @param uriTemplate The uri template
     * @param providerName The provider name
     * @return The URL path
     */
    protected String getPath(String uriTemplate, String providerName) {
        Map<String, Object> uriParams = HashMap.newHashMap(1);
        uriParams.put("provider", providerName);
        return UriTemplate.of(uriTemplate).expand(uriParams);
    }

    @Override
    public URL buildUrl(@Nullable HttpRequest<?> current, String path) {
        try {
            if (path.startsWith(HTTP)) {
                return new URL(path);
            }
            return UriBuilder.of(baseUrl(current))
                    .path(path)
                    .build()
                    .toURL();
        } catch (MalformedURLException e) {
            throw new RoutingException("Error building an absolute URL for the path", e);
        }
    }

    /**
     * Resolves the base (scheme, host and optional port) of the absolute URL. Returns the configured
     * {@link OauthConfiguration#getBaseUrl()} when present; otherwise the host resolved from the request.
     *
     * @param current The current request
     * @return The base URL
     * @since 5.4.0
     */
    protected String baseUrl(@Nullable HttpRequest<?> current) {
        return baseUrl != null ? baseUrl : hostResolver.resolve(current);
    }
}
