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

import io.micronaut.core.util.AntPathMatcher;
import io.micronaut.core.util.PathMatcher;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.RouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * An abstract class with common functionality for Security Rule implementations which
 * opt to express their configuration as a List of {@link InterceptUrlMapPattern}.
 *
 * @author James Kleeh
 * @since 1.0
 */
abstract class InterceptUrlMapRule extends AbstractSecurityRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = 0;

    private static final Logger LOG = LoggerFactory.getLogger(InterceptUrlMapRule.class);

    private final AntPathMatcher pathMatcher;

    /**
     * @param rolesFinder Roles Parser
     */
    @Inject
    public InterceptUrlMapRule(RolesFinder rolesFinder) {
        super(rolesFinder);
        this.pathMatcher = PathMatcher.ANT;
    }

    /**
     * Provides a list of {@link InterceptUrlMapPattern} which will be used to provide {@link SecurityRule}.
     * @return List of {@link InterceptUrlMapPattern}
     */
    protected abstract List<InterceptUrlMapPattern> getPatternList();

    /**
     * If no configured pattern matches the request, return {@link SecurityRuleResult#UNKNOWN}.
     * Reads the rules in order. The first matched rule will be used for determining authorization.
     *
     * @param request The current request
     * @param routeMatch The matched route
     * @param claims The claims from the token. Null if not authenticated
     * @return The result
     */
    @Override
    public SecurityRuleResult check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
        final String path = request.getUri().getPath();
        final HttpMethod httpMethod = request.getMethod();

        Predicate<InterceptUrlMapPattern> exactMatch = p -> pathMatcher.matches(p.getPattern(), path) && p.getHttpMethod().isPresent() && httpMethod.equals(p.getHttpMethod().get());
        Predicate<InterceptUrlMapPattern> uriPatternMatchOnly = p -> pathMatcher.matches(p.getPattern(), path) && !p.getHttpMethod().isPresent();

        Optional<InterceptUrlMapPattern> matchedPattern = getPatternList()
                .stream()
                .filter(exactMatch)
                .findFirst();

        // if we don't get an exact match try to find a match by the uri pattern
        if (!matchedPattern.isPresent()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No url map pattern exact match found for path [{}] and method [{}]. Searching in patterns with no defined method.", path, httpMethod);
            }
            matchedPattern = getPatternList()
                    .stream()
                    .filter(uriPatternMatchOnly)
                    .findFirst();

            if (LOG.isDebugEnabled()) {
                if (matchedPattern.isPresent()) {
                    LOG.debug("Url map pattern found for path [{}]. Comparing roles.", path);
                } else {
                    LOG.debug("No url map pattern match found for path [{}]. Returning unknown.", path);
                }
            }
        }

        return matchedPattern
                .map(pattern -> compareRoles(pattern.getAccess(), getRoles(claims)))
                .orElse(SecurityRuleResult.UNKNOWN);
    }
}
