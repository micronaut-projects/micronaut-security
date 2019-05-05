/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.web.router.exceptions.RoutingException;

import javax.annotation.Nullable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link OauthRouteUrlBuilder}
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class DefaultOauthRouteUrlBuilder implements OauthRouteUrlBuilder {

    private final HostResolver hostResolver;
    private final String loginUriTemplate;
    private final String callbackUriTemplate;
    private final String logoutUriTemplate;

    /**
     * @param hostResolver The host resolver
     * @param oauthConfigurationProperties The oauth configuration
     */
    DefaultOauthRouteUrlBuilder(HostResolver hostResolver,
                                OauthConfigurationProperties oauthConfigurationProperties) {
        this.hostResolver = hostResolver;
        this.loginUriTemplate = oauthConfigurationProperties.getLoginUri();
        this.callbackUriTemplate = oauthConfigurationProperties.getCallbackUri();
        this.logoutUriTemplate = oauthConfigurationProperties.getOpenid().getLogoutUri();
    }

    @Override
    public URL buildLoginUrl(@Nullable HttpRequest originating, String providerName) {
        return build(originating, providerName, loginUriTemplate);
    }

    @Override
    public URL buildCallbackUrl(@Nullable HttpRequest originating, String providerName) {
        return build(originating, providerName, callbackUriTemplate);
    }

    @Override
    public URL buildLogoutUrl(@Nullable HttpRequest originating, String providerName) {
        return build(originating, providerName, logoutUriTemplate);
    }

    /**
     * Builds a URL with the provided arguments
     *
     * @param originating The originating request
     * @param providerName The oauth provider name
     * @param uriTemplate The URI template
     * @return The URL
     */
    protected URL build(@Nullable HttpRequest originating, String providerName, String uriTemplate) {
        try {
            return UriBuilder.of(hostResolver.resolve(originating))
                    .path(getPath(uriTemplate, providerName))
                    .build()
                    .toURL();
        } catch (MalformedURLException e) {
            throw new RoutingException("Error building a URL for an oauth controller route", e);
        }
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
}
