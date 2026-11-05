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
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpHeaders;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.client.ProxyHttpClient;
import io.micronaut.http.filter.FilterPatternStyle;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * A filter which proxies GET requests to paths /.well-known/oauth-authorization-server or /.well-known/openid-configuration to an authorization server.
 * This filter is loaded only if {@link WellKnownProxyFilterCondition} condition evaluates to true.
 * <p>
 * The request sent to the authorization server is a fresh {@code GET} without the caller's headers (such as {@code Cookie} or {@code Authorization}),
 * cookies or query string. Only a successful JSON response from the authorization server is relayed, and only a fixed set of
 * its headers (never {@code Set-Cookie}) is copied to the response served from the application's origin.
 */
@Requires(condition = WellKnownProxyFilterCondition.class)
@Requires(classes = HttpRequest.class)
@Requires(beans = ProxyHttpClient.class)
@Filter(value = WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH + "|" + WellKnownProxyFilter.OPENID_CONFIGURATION_PATH,
    patternStyle = FilterPatternStyle.REGEX)
@Internal
final class WellKnownProxyFilter implements HttpServerFilter {

    static final String OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";
    static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

    private static final Logger LOG = LoggerFactory.getLogger(WellKnownProxyFilter.class);
    private static final String X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    private static final String NOSNIFF = "nosniff";

    /**
     * Response headers of the authorization server which are relayed to the caller. Everything else, notably {@code Set-Cookie}, is dropped.
     */
    private static final Set<String> RELAYED_RESPONSE_HEADERS = caseInsensitiveSet(
        HttpHeaders.CONTENT_TYPE,
        HttpHeaders.CONTENT_LENGTH,
        HttpHeaders.CACHE_CONTROL,
        HttpHeaders.EXPIRES,
        HttpHeaders.ETAG,
        HttpHeaders.LAST_MODIFIED
    );

    @Nullable
    private final WellKnownProxySettings settings;
    private final ProxyHttpClient proxyHttpClient;
    private final @Nullable HttpBodyReleaser httpBodyReleaser;

    WellKnownProxyFilter(@Nullable HttpBodyReleaser httpBodyReleaser,
                         List<OauthClientConfiguration> oauthClientConfigurations,
                         ProxyHttpClient proxyHttpClient) {
        this.httpBodyReleaser = httpBodyReleaser;
        this.settings = WellKnownProxyFilterCondition.issuer(oauthClientConfigurations);
        this.proxyHttpClient = proxyHttpClient;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        if (proceed(request)) {
            return chain.proceed(request);
        }
        return Flux.from(proxyHttpClient.proxy(upstreamRequest(request)))
            .map(this::sanitizeResponse)
            .onErrorResume(WellKnownProxyFilter::badGatewayOnFailure);
    }

    private static Publisher<MutableHttpResponse<?>> badGatewayOnFailure(Throwable throwable) {
        if (LOG.isWarnEnabled()) {
            LOG.warn("Failed to reach the authorization server for a well-known request: {}", throwable.toString());
        }
        return Flux.just(badGateway());
    }

    private static MutableHttpResponse<?> badGateway() {
        return HttpResponse.status(HttpStatus.BAD_GATEWAY)
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .header(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    }

    /**
     * Builds the request sent to the authorization server: a fresh GET for the well-known path at the issuer's origin.
     * No header, cookie or query string of the incoming request is forwarded.
     * @param request The incoming request
     * @return The request to send to the authorization server
     */
    @NonNull
    MutableHttpRequest<?> upstreamRequest(@NonNull HttpRequest<?> request) {
        URL issuer = settings.issuer();
        String path = OPENID_CONFIGURATION_PATH.equals(request.getPath())
            ? OPENID_CONFIGURATION_PATH
            : OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH;
        URI uri = UriBuilder.of(path)
            .scheme(issuer.getProtocol())
            .host(issuer.getHost())
            .port(issuer.getPort())
            .build();
        return HttpRequest.GET(uri).accept(MediaType.APPLICATION_JSON_TYPE);
    }

    /**
     * Only a successful JSON response is relayed, and only with the headers in {@link #RELAYED_RESPONSE_HEADERS}.
     * Anything else is answered with {@code 502 Bad Gateway} without a body.
     * @param upstream The authorization server response
     * @return The response served to the caller
     */
    @NonNull
    MutableHttpResponse<?> sanitizeResponse(@NonNull MutableHttpResponse<?> upstream) {
        if (!isSuccess(upstream) || !isJson(upstream)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Rejecting authorization server well-known response with status {} and content type {}",
                    upstream.code(), upstream.getContentType().map(MediaType::toString).orElse("none"));
            }
            discardBody(upstream);
            return badGateway();
        }
        MutableHttpHeaders headers = upstream.getHeaders();
        for (String name : new ArrayList<>(headers.names())) {
            if (!RELAYED_RESPONSE_HEADERS.contains(name)) {
                headers.remove(name);
            }
        }
        headers.set(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
        return upstream;
    }

    private static boolean isSuccess(@NonNull HttpResponse<?> response) {
        int code = response.code();
        return code >= HttpStatus.OK.getCode() && code < HttpStatus.MULTIPLE_CHOICES.getCode();
    }

    private static boolean isJson(@NonNull HttpResponse<?> response) {
        return response.getContentType()
            .map(contentType -> contentType.matches(MediaType.APPLICATION_JSON_TYPE)
                || MediaType.EXTENSION_JSON.equals(contentType.getExtension()))
            .orElse(false);
    }

    /**
     * Releases the body of a response which is not relayed so that the client connection is not held open.
     * @param response The discarded response
     */
    private void discardBody(@NonNull MutableHttpResponse<?> response) {
        if (httpBodyReleaser != null) {
            httpBodyReleaser.release(response);
        }
    }

    private static Set<String> caseInsensitiveSet(String... names) {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        set.addAll(List.of(names));
        return set;
    }

    boolean proceed(@NonNull HttpRequest<?> request) {
        if (settings == null || settings.issuer() == null || request.getMethod() != HttpMethod.GET) {
            return true;
        }
        String path = request.getPath();
        if (OPENID_CONFIGURATION_PATH.equals(path)) {
            return !settings.proxyWellKnownOpenidConfiguration();
        }
        if (OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH.equals(path)) {
            return !settings.proxyWellKnownOauthAuthorizationServer();
        }
        // The @Filter regex also matches paths where '.' stands for another character; never proxy those.
        return true;
    }
}
