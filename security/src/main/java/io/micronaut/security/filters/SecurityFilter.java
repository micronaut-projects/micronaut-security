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
import io.micronaut.core.annotation.Nullable;
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
import io.micronaut.web.router.RouteMatch;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

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

    /**
     * @param securityRules          The list of security rules that will allow or reject the request
     * @param authenticationFetchers List of {@link AuthenticationFetcher} beans in the context.
     * @param securityConfiguration  The security configuration
     */
    public SecurityFilter(Collection<SecurityRule<HttpRequest<?>>> securityRules,
                          Collection<AuthenticationFetcher<HttpRequest<?>>> authenticationFetchers,
                          SecurityConfiguration securityConfiguration) {
        this.securityRules = securityRules;
        this.authenticationFetchers = authenticationFetchers;
        this.securityConfiguration = securityConfiguration;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        request.getAttributes().put(KEY, true);

        // Authentication fetchers may complete asynchronously on a thread bound to another request's propagated
        // context (for example when several requests wait for the same remote JWK Set). Bind the propagated context
        // of this request around each fetcher, so that what a fetcher does with its result after an asynchronous
        // validation is bound to this request too, and resume the rule checks within that context.
        PropagatedContext propagatedContext = PropagatedContext.getOrEmpty();
        return Flux.fromIterable(authenticationFetchers)
                .flatMap(authenticationFetcher -> inContext(propagatedContext, () -> authenticationFetcher.fetchAuthentication(request)))
                .next()
                .flatMap(authentication -> Mono.from(inContext(propagatedContext, () -> createResponse(authentication, request, chain))))
                .switchIfEmpty(Mono.from(inContext(propagatedContext, () -> createResponse(null, request, chain))));
    }

    private Publisher<MutableHttpResponse<?>> createResponse(@Nullable Authentication authentication,
                                                             HttpRequest<?> request,
                                                             ServerFilterChain chain) {
        ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withAuthentication(authentication);
        logAuthenticationAttributes(authentication);
        return checkRules(request, chain, authentication);
    }

    private void logAuthenticationAttributes(@Nullable Authentication authentication) {
        if (authentication != null && LOG.isDebugEnabled()) {
            Map<String, Object> attributes = authentication.getAttributes();
            LOG.debug("Attributes: {}", attributes
                    .entrySet()
                    .stream()
                    .map((entry) -> entry.getKey() + "=>" + (entry.getValue() != null ? entry.getValue().toString() : "null"))
                    .collect(Collectors.joining(", ")));
        }
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
                    RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);
                    // no rule found for the given request
                    if (routeMatch == null && !securityConfiguration.isRejectNotFound()) {
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
