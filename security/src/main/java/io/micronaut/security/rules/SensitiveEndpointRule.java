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

import io.micronaut.http.HttpRequest;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Singleton;
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

    private static final Logger LOG = LoggerFactory.getLogger(InterceptUrlMapRule.class);

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
    SensitiveEndpointRule(EndpointSensitivityProcessor endpointSensitivityProcessor) {
        this.endpointMethods = endpointSensitivityProcessor.getEndpointMethods();
    }

    @Override
    public SecurityRuleResult check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
        if (routeMatch instanceof MethodBasedRouteMatch) {
            ExecutableMethod method = ((MethodBasedRouteMatch) routeMatch).getExecutableMethod();

            if (endpointMethods.containsKey(method)) {
                Boolean sensitive = endpointMethods.get(method);
                if (claims == null && sensitive) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("The endpoint method [{}] is sensitive and no authentication was found. Rejecting the request", method);
                    }
                    return SecurityRuleResult.REJECTED;
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("The endpoint method [{}] is not sensitive or the request was authenticated. Allowing the request", method);
                    }
                    return SecurityRuleResult.ALLOWED;
                }
            }
        }
        return SecurityRuleResult.UNKNOWN;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
