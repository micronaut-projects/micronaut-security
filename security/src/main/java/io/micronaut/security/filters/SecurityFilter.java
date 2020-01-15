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

package io.micronaut.security.filters;

import io.micronaut.http.*;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.OncePerRequestHttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.handlers.RejectionHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.web.router.RouteMatch;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
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
@Filter("/**")
public class SecurityFilter extends OncePerRequestHttpServerFilter {

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
    protected final Integer order;

    protected final Collection<SecurityRule> securityRules;
    protected final Collection<AuthenticationFetcher> authenticationFetchers;
    protected final RejectionHandler rejectionHandler;

    /**
     * @param securityRules               The list of rules that will allow or reject the request
     * @param authenticationFetchers      List of {@link AuthenticationFetcher} beans in the context.
     * @param rejectionHandler            Bean which handles routes which need to be rejected
     * @param securityFilterOrderProvider filter order provider
     */
    public SecurityFilter(Collection<SecurityRule> securityRules,
                          Collection<AuthenticationFetcher> authenticationFetchers,
                          RejectionHandler rejectionHandler,
                          @Nullable SecurityFilterOrderProvider securityFilterOrderProvider) {
        this.securityRules = securityRules;
        this.authenticationFetchers = authenticationFetchers;
        this.rejectionHandler = rejectionHandler;
        this.order = securityFilterOrderProvider != null ? securityFilterOrderProvider.getOrder() : 0;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    protected Publisher<MutableHttpResponse<?>> doFilterOnce(HttpRequest<?> request, ServerFilterChain chain) {
        String method = request.getMethod().toString();
        String path = request.getPath();
        RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);
        if (hasMultipleSecureAnnotations(routeMatch)) {
            if (LOG.isErrorEnabled()) {
                LOG.error("The route [" + path + "] has multiple security annotations. Please use either @Secured or javax.annotation.security annotations (@RolesAllowed, @PermitAll or @DenyAll)");
            }
            return Flowable.just(HttpResponse.serverError());
        }

        return Flowable.fromIterable(authenticationFetchers)
            .flatMap(authenticationFetcher -> authenticationFetcher.fetchAuthentication(request))
            .firstElement()
            .doOnEvent((authentication, throwable) -> {
                if (authentication != null) {
                    request.setAttribute(AUTHENTICATION, authentication);
                    Map<String, Object> attributes = authentication.getAttributes();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Attributes: {}", attributes
                                .entrySet()
                                .stream()
                                .map((entry) -> entry.getKey() + "=>" + entry.getValue().toString())
                                .collect(Collectors.joining(", ")));
                    }
                } else {
                    request.setAttribute(AUTHENTICATION, null);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No Authentication fetched for request. {} {}.", method, path);
                    }
                }
            })
            .toFlowable()
            .flatMap(authentication -> checkRules(request, chain, routeMatch, authentication.getAttributes(), true))
            .switchIfEmpty(Flowable.defer(() -> checkRules(request, chain, routeMatch, null, false)));
    }

    private boolean hasMultipleSecureAnnotations(RouteMatch<?> routeMatch) {
        if (routeMatch != null) {
            return routeMatch.isAnnotationPresent(Secured.class) && (
                        routeMatch.isAnnotationPresent(RolesAllowed.class) ||
                        routeMatch.isAnnotationPresent(PermitAll.class) ||
                        routeMatch.isAnnotationPresent(DenyAll.class)
            );
        } else {
            return false;
        }
    }

    /**
     * Check the security rules against the provided arguments.
     *
     * @param request The request
     * @param chain The server chain
     * @param routeMatch The route match
     * @param attributes The authentication attributes
     * @param forbidden Whether a rejection should be forbidden
     * @return A response publisher
     */
    protected Publisher<MutableHttpResponse<?>> checkRules(HttpRequest<?> request,
                                                           ServerFilterChain chain,
                                                           @Nullable RouteMatch routeMatch,
                                                           @Nullable Map<String, Object> attributes,
                                                           boolean forbidden) {
        String method = request.getMethod().toString();
        String path = request.getPath();
        for (SecurityRule rule : securityRules) {
            SecurityRuleResult result = rule.check(request, routeMatch, attributes);
            if (result == SecurityRuleResult.REJECTED) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unauthorized request {} {}. The rule provider {} rejected the request.", method, path, rule.getClass().getName());
                }
                request.setAttribute(REJECTION, forbidden ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED);
                return rejectionHandler.reject(request, forbidden);
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
        //no rule found for the given request, reject
        request.setAttribute(REJECTION, forbidden ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED);
        return rejectionHandler.reject(request, forbidden);
    }
}
