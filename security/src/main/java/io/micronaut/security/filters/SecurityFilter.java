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
package io.micronaut.security.filters;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.management.endpoint.EndpointsFilter;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.web.router.RouteMatch;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.core.annotation.Nullable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Security Filter.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Replaces(EndpointsFilter.class)
@Filter(Filter.MATCH_ALL_PATTERN)
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

    protected final Collection<SecurityRule> securityRules;
    protected final Collection<AuthenticationFetcher> authenticationFetchers;

    protected final SecurityConfiguration securityConfiguration;

    /**
     * @param securityRules          The list of rules that will allow or reject the request
     * @param authenticationFetchers List of {@link AuthenticationFetcher} beans in the context.
     * @param securityConfiguration  The security configuration
     */
    public SecurityFilter(Collection<SecurityRule> securityRules,
                          Collection<AuthenticationFetcher> authenticationFetchers,
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
        populateWithOldKey(request);
        RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);

        return Flux.fromIterable(authenticationFetchers)
                .flatMap(authenticationFetcher -> authenticationFetcher.fetchAuthentication(request))
                .next()
                .flatMap(authentication -> Mono.from(createResponse(authentication, request, chain, routeMatch)))
                .switchIfEmpty(Flux.<MutableHttpResponse<?>>defer(() -> createResponse(null, request, chain, routeMatch))
                        .next());
    }

    /**
     * Remove once {@link io.micronaut.http.filter.OncePerRequestHttpServerFilter} is deleted.
     */
    @Deprecated
    private void populateWithOldKey(HttpRequest<?> request) {
        request.getAttributes().put("micronaut.once." + SecurityFilter.class.getSimpleName(), true);
    }

    private Publisher<MutableHttpResponse<?>> createResponse(@Nullable Authentication authentication,
                                                             HttpRequest<?> request,
                                                             ServerFilterChain chain,
                                                             RouteMatch<?> routeMatch) {
        request.setAttribute(AUTHENTICATION, authentication);
        logAuthenticationAttributes(authentication);
        return checkRules(request, chain, routeMatch, authentication);
    }

    private void logAuthenticationAttributes(@Nullable Authentication authentication) {
        if (authentication != null && LOG.isDebugEnabled()) {
            Map<String, Object> attributes = authentication.getAttributes();
            LOG.debug("Attributes: {}", attributes
                    .entrySet()
                    .stream()
                    .map((entry) -> entry.getKey() + "=>" + entry.getValue().toString())
                    .collect(Collectors.joining(", ")));
        }
    }

    /**
     * Check the security rules against the provided arguments.
     *
     * @param request The request
     * @param chain The server chain
     * @param routeMatch The route match
     * @param authentication The authentication
     * @return A response publisher
     */
    protected Publisher<MutableHttpResponse<?>> checkRules(HttpRequest<?> request,
                                                           ServerFilterChain chain,
                                                           @Nullable RouteMatch<?> routeMatch,
                                                           @Nullable Authentication authentication) {
        boolean forbidden = authentication != null;
        String method = request.getMethod().toString();
        String path = request.getPath();
        Map<String, Object> attributes = authentication != null ? authentication.getAttributes() : null;
        for (SecurityRule rule : securityRules) {
            SecurityRuleResult result = rule.check(request, routeMatch, attributes);
            if (result == SecurityRuleResult.REJECTED) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unauthorized request {} {}. The rule provider {} rejected the request.", method, path, rule.getClass().getName());
                }
                request.setAttribute(REJECTION, forbidden ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED);
                return Publishers.just(new AuthorizationException(authentication));
            }
            if (result == SecurityRuleResult.ALLOWED) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authorized request {} {}. The rule provider {} authorized the request.", method, path, rule.getClass().getName());
                }
                return chain.proceed(request);
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authorized request {} {}. No rule provider authorized or rejected the request.", method, path);
        }
        //no rule found for the given request
        if (routeMatch == null && !securityConfiguration.isRejectNotFound()) {
            return chain.proceed(request);
        } else {
            request.setAttribute(REJECTION, forbidden ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED);
            return Publishers.just(new AuthorizationException(authentication));
        }
    }
}
