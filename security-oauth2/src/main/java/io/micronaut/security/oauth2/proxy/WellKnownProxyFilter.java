/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.proxy;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.client.ProxyHttpClient;
import io.micronaut.http.filter.FilterPatternStyle;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import jakarta.annotation.Nullable;
import org.reactivestreams.Publisher;

import java.net.URL;
import java.util.List;

/**
 * A filter which proxies GET requests to paths /.well-known/oauth-authorization-server or /.well-known/openid-configuration to an authorization server.
 * This filter is loaded only if {@link WellKnownProxyFilterCondition} condition evaluates to true.
 */
@Requires(condition = WellKnownProxyFilterCondition.class)
@Requires(classes = HttpRequest.class)
@Requires(beans = ProxyHttpClient.class)
@Filter(value = WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH + "|" + WellKnownProxyFilter.OPENID_CONFIGURATION_PATH,
    patternStyle = FilterPatternStyle.REGEX)
final class WellKnownProxyFilter implements HttpServerFilter {

    static final String OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";
    static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

    @Nullable
    private final WellKnownProxySettings settings;
    private final ProxyHttpClient proxyHttpClient;

    WellKnownProxyFilter(List<OauthClientConfiguration> oauthClientConfigurations,
                         ProxyHttpClient proxyHttpClient) {
        this.settings = WellKnownProxyFilterCondition.issuer(oauthClientConfigurations);
        this.proxyHttpClient = proxyHttpClient;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        if (proceed(request)) {
            return chain.proceed(request);
        }
        URL issuer = settings.issuer();
        return proxyHttpClient.proxy(request.mutate().uri(b -> b
            .host(issuer.getHost())
            .scheme(issuer.getProtocol())
            .port(issuer.getPort())));
    }

    boolean proceed(@NonNull HttpRequest<?> request) {
        return settings == null
            || settings.issuer() == null
            || request.getMethod() != HttpMethod.GET
            || (request.getPath().equals(OPENID_CONFIGURATION_PATH) && !settings.proxyWellKnownOpenidConfiguration())
            || (request.getPath().equals(OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH) && !settings.proxyWellKnownOauthAuthorizationServer());
    }
}
