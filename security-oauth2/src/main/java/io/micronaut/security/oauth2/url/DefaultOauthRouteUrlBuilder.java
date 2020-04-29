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
package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.web.router.exceptions.RoutingException;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Singleton;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OauthRouteUrlBuilder}
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultOauthRouteUrlBuilder implements OauthRouteUrlBuilder {

    private final HttpHostResolver hostResolver;
    private final String loginUriTemplate;
    private final String callbackUriTemplate;

    /**
     * @param hostResolver The host resolver
     * @param oauthConfigurationProperties The oauth configuration
     */
    DefaultOauthRouteUrlBuilder(HttpHostResolver hostResolver,
                                OauthConfigurationProperties oauthConfigurationProperties) {
        this.hostResolver = hostResolver;
        this.loginUriTemplate = oauthConfigurationProperties.getLoginUri();
        this.callbackUriTemplate = oauthConfigurationProperties.getCallbackUri();
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
     * Builds a URL with the provided arguments
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
     * Builds the path portion of the URL
     *
     * @param uriTemplate The uri template
     * @param providerName The provider name
     * @return The URL path
     */
    protected String getPath(String uriTemplate, String providerName) {
        Map<String, Object> uriParams = new HashMap<>(1);
        uriParams.put("provider", providerName);
        return UriTemplate.of(uriTemplate).expand(uriParams);
    }

    @Override
    public URL buildUrl(@Nullable HttpRequest<?> current, String path) {
        try {
            return UriBuilder.of(hostResolver.resolve(current))
                    .path(path)
                    .build()
                    .toURL();
        } catch (MalformedURLException e) {
            throw new RoutingException("Error building an absolute URL for the path", e);
        }
    }
}
