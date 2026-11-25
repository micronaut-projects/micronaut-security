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
package io.micronaut.security.filters;

import io.micronaut.context.annotation.Requires;
import io.micronaut.web.router.RouteAttributes;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.propagation.ReactivePropagation;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.utils.LoggingUtils;
import jakarta.inject.Inject;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.function.Supplier;

/**
 * Security Filter.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(property = SecurityFilterConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(classes = { HttpServerFilter.class })
@Filter("${" + SecurityFilterConfigurationProperties.PREFIX + ".pattern:" + Filter.MATCH_ALL_PATTERN + "}")
public class SecurityFilter implements HttpServerFilter {

    public static final String KEY = "io.micronaut.security.filters." + SecurityFilter.class.getSimpleName();

    /**
     * The attribute used to store the authentication object in the request.
     */
    public static final CharSequence AUTHENTICATION = HttpAttributes.PRINCIPAL.toString();

    /**
     * The attribute used to store if the request was rejected and why.
     */
    public static final CharSequence REJECTION = "micronaut.security.REJECTION";

    /**
     * The attribute used to store a valid token in the request.
     */
    public static final CharSequence TOKEN = "micronaut.TOKEN";

    private static final Logger LOG = LoggerFactory.getLogger(SecurityFilter.class);

    /**
     * The order of the Security Filter.
     */
    private static final Integer ORDER = ServerFilterPhase.SECURITY.order();

    protected final Collection<SecurityRule<HttpRequest<?>>> securityRules;
    protected final Collection<AuthenticationFetcher<HttpRequest<?>>> authenticationFetchers;

    protected final SecurityConfiguration securityConfiguration;
    private final StaticResourceAuthenticationBypass<HttpRequest<?>> staticResourceAuthenticationBypass;
    private final boolean staticResourceAuthenticationBypassEnabled;
    @Nullable
    private final StaticResourceMatcher<HttpRequest<?>> staticResourceMatcher;

    /**
     * @param securityRules          The list of security rules that will allow or reject the request
     * @param authenticationFetchers List of {@link AuthenticationFetcher} beans in the context.
     * @param securityConfiguration  The security configuration
     * @deprecated Use {@link #SecurityFilter(Collection, Collection, SecurityConfiguration, SecurityFilterConfiguration, StaticResourceAuthenticationBypass)}.
     */
    @Deprecated(forRemoval = true, since = "5.4.0")
    public SecurityFilter(Collection<SecurityRule<HttpRequest<?>>> securityRules,
                          Collection<AuthenticationFetcher<HttpRequest<?>>> authenticationFetchers,
                          SecurityConfiguration securityConfiguration) {
        this.securityRules = securityRules;
        this.authenticationFetchers = authenticationFetchers;
        this.securityConfiguration = securityConfiguration;
        this.staticResourceAuthenticationBypass = null;
        this.staticResourceAuthenticationBypassEnabled = false;
        this.staticResourceMatcher = null;
        warnIfNoStaticResourceMatcher(securityConfiguration, null);
    }

    /**
     * @param securityRules The list of security rules that will allow or reject the request
     * @param authenticationFetchers List of {@link AuthenticationFetcher} beans in the context
     * @param securityConfiguration The security configuration
     * @param securityFilterConfiguration The security filter configuration
     * @param staticResourceAuthenticationBypass Determines whether authentication can be skipped for static resources
     * @since 5.4.0
     * @deprecated Use {@link #SecurityFilter(Collection, Collection, SecurityConfiguration, SecurityFilterConfiguration, StaticResourceAuthenticationBypass, StaticResourceMatcher)}.
     */
    @Deprecated(forRemoval = true, since = "5.5.2")
    public SecurityFilter(Collection<SecurityRule<HttpRequest<?>>> securityRules,
                          Collection<AuthenticationFetcher<HttpRequest<?>>> authenticationFetchers,
                          SecurityConfiguration securityConfiguration,
                          SecurityFilterConfiguration securityFilterConfiguration,
                          @Nullable StaticResourceAuthenticationBypass<HttpRequest<?>> staticResourceAuthenticationBypass) {
        this(securityRules, authenticationFetchers, securityConfiguration, securityFilterConfiguration, staticResourceAuthenticationBypass, (StaticResourceMatcher<HttpRequest<?>>) null);
    }

    /**
     * @param securityRules The list of security rules that will allow or reject the request
     * @param authenticationFetchers List of {@link AuthenticationFetcher} beans in the context
     * @param securityConfiguration The security configuration
     * @param securityFilterConfiguration The security filter configuration
     * @param staticResourceAuthenticationBypass Determines whether authentication can be skipped for static resources
     * @param staticResourceMatcher Tells whether the server could serve a request that matches no route as a static resource, used to reject static resources that no security rule covers even when {@code micronaut.security.reject-not-found} is disabled. When {@code null}, the filter fails closed and rejects every request that matches no route, regardless of {@code micronaut.security.reject-not-found}.
     * @since 5.5.2
     */
    @Inject
    public SecurityFilter(Collection<SecurityRule<HttpRequest<?>>> securityRules,
                          Collection<AuthenticationFetcher<HttpRequest<?>>> authenticationFetchers,
                          SecurityConfiguration securityConfiguration,
                          SecurityFilterConfiguration securityFilterConfiguration,
                          @Nullable StaticResourceAuthenticationBypass<HttpRequest<?>> staticResourceAuthenticationBypass,
                          @Nullable StaticResourceMatcher<HttpRequest<?>> staticResourceMatcher) {
        this.securityRules = securityRules;
        this.authenticationFetchers = authenticationFetchers;
        this.securityConfiguration = securityConfiguration;
        this.staticResourceAuthenticationBypass = staticResourceAuthenticationBypass;
        this.staticResourceAuthenticationBypassEnabled = securityFilterConfiguration.isStaticResourceAuthenticationBypass();
        this.staticResourceMatcher = staticResourceMatcher;
        warnIfNoStaticResourceMatcher(securityConfiguration, staticResourceMatcher);
    }

    private static void warnIfNoStaticResourceMatcher(SecurityConfiguration securityConfiguration,
                                                      @Nullable StaticResourceMatcher<HttpRequest<?>> staticResourceMatcher) {
        if (staticResourceMatcher == null && !securityConfiguration.isRejectNotFound() && LOG.isWarnEnabled()) {
            LOG.warn("No StaticResourceMatcher is available to the SecurityFilter. Requests that match no route and that no security rule allows are rejected regardless of micronaut.security.reject-not-found, because the filter cannot tell whether the server would serve them as a static resource. Create the filter with a StaticResourceMatcher to answer 404 for unknown routes.");
        }
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        request.getAttributes().put(KEY, true);

        if (staticResourceAuthenticationBypassEnabled
            && staticResourceAuthenticationBypass != null
            && staticResourceAuthenticationBypass.shouldBypass(request)) {
            return createResponse(null, request, chain);
        }

        // Authentication fetchers may complete asynchronously on a thread bound to another request's propagated
        // context (for example when several requests wait for the same remote JWK Set). Bind the propagated context
        // of this request around each fetcher, so that what a fetcher does with its result after an asynchronous
        // validation is bound to this request too, and resume the rule checks within that context.
        PropagatedContext propagatedContext = PropagatedContext.getOrEmpty();
        return Flux.fromIterable(authenticationFetchers)
                .concatMap(authenticationFetcher -> inContext(propagatedContext, () -> authenticationFetcher.fetchAuthentication(request)))
                .next()
                .flatMap(authentication -> Mono.from(inContext(propagatedContext, () -> createResponse(authentication, request, chain))))
                .switchIfEmpty(Mono.from(inContext(propagatedContext, () -> createResponse(null, request, chain))));
    }

    private Publisher<MutableHttpResponse<?>> createResponse(@Nullable Authentication authentication,
                                                             HttpRequest<?> request,
                                                             ServerFilterChain chain) {
        ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withAuthentication(authentication);
        LoggingUtils.logAuthenticationAttributes(LOG, authentication);
        return checkRules(request, chain, authentication);
    }

    /**
     * Check the security rules against the provided arguments.
     *
     * @param request The request
     * @param chain The server chain
     * @param authentication The authentication
     * @return A response publisher
     */
    protected Publisher<MutableHttpResponse<?>> checkRules(HttpRequest<?> request,
                                                           ServerFilterChain chain,
                                                           @Nullable Authentication authentication) {
        boolean forbidden = authentication != null;
        String method = request.getMethod().toString();
        String path = request.getPath();
        // Each rule, and the rest of the filter chain, may be resumed on a thread bound to the propagated context of
        // another request. Bind the context of this request explicitly around each of them.
        PropagatedContext propagatedContext = PropagatedContext.getOrEmpty();

        return Flux.fromIterable(securityRules)
                .concatMap(rule -> Mono.from(inContext(propagatedContext, () -> rule.check(request, authentication)))
                                        .defaultIfEmpty(SecurityRuleResult.UNKNOWN)
                                        // Ideally should return just empty but filter the unknowns
                                        .filter(result -> result != SecurityRuleResult.UNKNOWN)
                                        .doOnSuccess(result -> logResult((SecurityRuleResult) result, method, path, rule)))
                .next()
                .flatMapMany(result -> {
                    if (result == SecurityRuleResult.REJECTED) {
                        ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withRejectionStatus(forbidden ? HttpStatus.FORBIDDEN.getCode() : HttpStatus.UNAUTHORIZED.getCode());
                        return Mono.error(new AuthorizationException(authentication));
                    } else if (result == SecurityRuleResult.ALLOWED) {
                        return inContext(propagatedContext, () -> chain.proceed(request));
                    } else {
                        return Mono.empty();
                    }
                })
                .switchIfEmpty(Flux.defer(() -> {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(
                                "Authorized request {} {}. No rule provider authorized or rejected the request.",
                                method,
                                path);
                    }
                    // Only check presence; the route match is owned by the request pipeline and must not be closed.
                    boolean routeMatchPresent = RouteAttributes.getRouteMatch(request).isPresent();
                    // no rule found for the given request
                    if (!routeMatchPresent && !securityConfiguration.isRejectNotFound() && !mayBeStaticResource(request)) {
                        return inContext(propagatedContext, () -> chain.proceed(request));
                    } else {
                        ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withRejectionStatus(forbidden ? HttpStatus.FORBIDDEN.getCode() : HttpStatus.UNAUTHORIZED.getCode());
                        return Mono.error(new AuthorizationException(authentication));
                    }
                }));
    }

    private static <T> Publisher<T> inContext(PropagatedContext propagatedContext, Supplier<Publisher<T>> supplier) {
        return ReactivePropagation.propagate(propagatedContext, Flux.defer(supplier));
    }

    /**
     * A request that matches no route may still be served by the server as a static resource. The
     * {@link StaticResourceMatcher} tells, so that a static resource that no security rule covers is rejected instead
     * of being served when {@code micronaut.security.reject-not-found} is disabled. Without a matcher, which only
     * happens with the deprecated constructors, the filter cannot tell and fails closed: every such request is
     * treated as a possible static resource.
     *
     * @param request The request
     * @return Whether the request may be served as a static resource
     */
    private boolean mayBeStaticResource(HttpRequest<?> request) {
        return staticResourceMatcher == null || staticResourceMatcher.isStaticResource(request);
    }

    private void logResult(SecurityRuleResult result, String method, String path, Ordered ordered) {
        if (LOG.isDebugEnabled()) {
            if (result == SecurityRuleResult.REJECTED) {
                LOG.debug(
                        "Unauthorized request {} {}. The rule provider {} rejected the request.",
                        method,
                        path,
                        ordered.getClass().getName());
            } else if (result == SecurityRuleResult.ALLOWED) {
                LOG.debug(
                        "Authorized request {} {}. The rule provider {} authorized the request.",
                        method,
                        path,
                        ordered.getClass().getName());
            }
        }
    }
}
