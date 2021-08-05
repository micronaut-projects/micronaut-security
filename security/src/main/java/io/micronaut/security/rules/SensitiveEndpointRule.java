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
package io.micronaut.security.rules;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.management.endpoint.beans.BeansEndpoint;
import io.micronaut.management.endpoint.env.EnvironmentEndpoint;
import io.micronaut.management.endpoint.health.HealthEndpoint;
import io.micronaut.management.endpoint.info.InfoEndpoint;
import io.micronaut.management.endpoint.loggers.LoggersEndpoint;
import io.micronaut.management.endpoint.refresh.RefreshEndpoint;
import io.micronaut.management.endpoint.routes.RoutesEndpoint;
import io.micronaut.management.endpoint.stop.ServerStopEndpoint;
import io.micronaut.management.endpoint.threads.ThreadDumpEndpoint;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Finds any sensitive endpoints and processes requests that match their
 * id. The user must be authenticated to execute sensitive requests.
 *
 * @author Sergio del Amo
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class SensitiveEndpointRule implements SecurityRule {
    /**
     * The order of the rule.
     */
    public static final Integer ORDER = 0;

    private static final Logger LOG = LoggerFactory.getLogger(SensitiveEndpointRule.class);
    private static final String ENDPOINTS_BEANS = "beans";
    private static final String ENDPOINTS_INFO = "info";
    private static final String ENDPOINTS_HEALTH = "health";
    private static final String ENDPOINTS_REFRESH = "refresh";
    private static final String ENDPOINTS_ROUTES = "routes";
    private static final String ENDPOINTS_LOGGERS = "loggers";
    private static final String ENDPOINTS_SERVER_STOP = "serverStop";
    private static final String ENDPOINTS_ENVIRONMENT = "environment";
    private static final String ENDPOINTS_THREAD_DUMP = "threadDump";

    /**
     * A map where the key represents the method of an endpoint
     * and the value represents the endpoints sensitivity.
     */
    protected final Map<ExecutableMethod, Boolean> endpointMethods;

    /**
     * Constructs the rule with the existing and default endpoint
     * configurations used to determine if a given endpoint is
     * sensitive.
     *
     * @param endpointSensitivityProcessor The endpoint configurations
     */
    public SensitiveEndpointRule(EndpointSensitivityProcessor endpointSensitivityProcessor) {
        this.endpointMethods = endpointSensitivityProcessor.getEndpointMethods();
    }

    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Authentication authentication) {
        if (routeMatch instanceof MethodBasedRouteMatch) {
            ExecutableMethod<?, ?> method = ((MethodBasedRouteMatch<?, ?>) routeMatch).getExecutableMethod();
            if (endpointMethods.containsKey(method)) {
                return check(request, authentication, method);
            }
        }
        return Mono.just(SecurityRuleResult.UNKNOWN);
    }

    /**
     * Evaluate the Endpoint's method.
     * @param request HTTP Request
     * @param authentication The authentication, or null if none found
     * @param method Route method
     * @return The Result
     */
    @NonNull
    protected Publisher<SecurityRuleResult> check(@NonNull HttpRequest<?> request,
                                                  @Nullable Authentication authentication,
                                                  @NonNull ExecutableMethod<?, ?> method) {

        Boolean sensitive = endpointMethods.get(method);
        if (sensitive) {
            if (authentication == null) {
                return checkSensitiveAnonymous(request, method);
            }
            return checkSensitiveAuthenticated(request, authentication, method);
        }
        return checkNotSensitive(request, authentication, method);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * Evaluates a sensitive endpoint for an authenticated user.
     * @param request HTTP Request
     * @param authentication The authentication, or null if none found
     * @param method Endpoint's method
     * @return The Result
     */
    @NonNull
    protected Publisher<SecurityRuleResult> checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                                        @NonNull Authentication authentication,
                                                                        @NonNull ExecutableMethod<?, ?> method) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("authentication was found for sensitive {} endpoint. Allowing the request.", endpointName(method));
        }
        return Mono.just(SecurityRuleResult.ALLOWED);
    }

    /**
     * Evaluates a sensitive endpoint for an anonymous user.
     * @param request HTTP Request
     * @param method Endpoint's method
     * @return The Result
     */
    @NonNull
    protected Publisher<SecurityRuleResult> checkSensitiveAnonymous(@NonNull HttpRequest<?> request,
                                                                    @NonNull ExecutableMethod<?, ?> method) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("{} endpoint is sensitive and no authentication was found. Rejecting the request.", endpointName(method));
        }
        return Mono.just(SecurityRuleResult.REJECTED);
    }

    /**
     * Evaluates a non sensitive endpoint.
     * @param request HTTP Request
     * @param authentication The authentication, or null if none found
     * @param method Endpoint's method
     * @return The Result
     */
    @NonNull
    protected Publisher<SecurityRuleResult> checkNotSensitive(@NonNull HttpRequest<?> request,
                                                              @Nullable Authentication authentication,
                                                              @NonNull ExecutableMethod<?, ?> method) {
        if (LOG.isTraceEnabled()) {
            LOG.debug("{} endpoint is not sensitive. Allowing the request.", endpointName(method));
        }
        return Mono.just(SecurityRuleResult.ALLOWED);
    }

    /**
     * @param method Endpoint's method
     * @return A string identifying the Endpoint
     */
    @NonNull
    protected String endpointName(@NonNull ExecutableMethod<?, ?> method) {
        Class<?> endpointClass = method.getDeclaringType();
        if (endpointClass == BeansEndpoint.class) {
            return ENDPOINTS_BEANS;
        } else if (endpointClass == InfoEndpoint.class) {
            return ENDPOINTS_INFO;
        } else if (endpointClass == HealthEndpoint.class) {
            return ENDPOINTS_HEALTH;
        } else if (endpointClass == RefreshEndpoint.class) {
            return ENDPOINTS_REFRESH;
        } else if (endpointClass == RoutesEndpoint.class) {
            return ENDPOINTS_ROUTES;
        } else if (endpointClass == LoggersEndpoint.class) {
            return ENDPOINTS_LOGGERS;
        } else if (endpointClass == ServerStopEndpoint.class) {
            return ENDPOINTS_SERVER_STOP;
        } else if (endpointClass == EnvironmentEndpoint.class) {
            return ENDPOINTS_ENVIRONMENT;
        } else if (endpointClass == ThreadDumpEndpoint.class) {
            return ENDPOINTS_THREAD_DUMP;
        }
        return method.getDeclaringType().getSimpleName();
    }
}
