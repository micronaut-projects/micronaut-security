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

@Requires(condition = WellKnownProxyFilterCondition.class)
@Filter(value = "/.well-known/oauth-authorization-server|/.well-known/openid-configuration",
    patternStyle = FilterPatternStyle.REGEX)
class WellKnownProxyFilter implements HttpServerFilter {

@Nullable
    private final URL issuer;
    private final ProxyHttpClient proxyHttpClient;

    WellKnownProxyFilter(List<OauthClientConfiguration> oauthClientConfigurations,
                         ProxyHttpClient proxyHttpClient) {
        this.issuer = WellKnownProxyFilterCondition.issuer(oauthClientConfigurations);
        this.proxyHttpClient = proxyHttpClient;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        if (issuer == null) {
            return chain.proceed(request);
        }
        return proxyHttpClient.proxy(request.mutate().uri(b ->
            b.host(issuer.getHost()).scheme(issuer.getProtocol()).port(issuer.getPort())));
    }
}
