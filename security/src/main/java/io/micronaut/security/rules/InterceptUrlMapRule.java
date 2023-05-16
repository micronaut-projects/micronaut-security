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
package io.micronaut.security.rules;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.AntPathMatcher;
import io.micronaut.core.util.PathMatcher;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.token.RolesFinder;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * An abstract class with common functionality for Security Rule implementations which
 * opt to express their configuration as a List of {@link InterceptUrlMapPattern}.
 *
 * @author James Kleeh
 * @since 1.0
 * @param <T> Route Match
 */
abstract class InterceptUrlMapRule<T> extends AbstractSecurityRule<T> {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = 0;

    private static final Logger LOG = LoggerFactory.getLogger(InterceptUrlMapRule.class);

    private final AntPathMatcher pathMatcher;

    /**
     * @param rolesFinder Roles Parser
     */
    protected InterceptUrlMapRule(RolesFinder rolesFinder) {
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
     * @param authentication The user authentication. Null if not authenticated
     * @return The result
     */
    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable T routeMatch, @Nullable Authentication authentication) {
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

        return Mono.from(matchedPattern
                .map(pattern -> compareRoles(pattern.getAccess(), getRoles(authentication)))
                .orElse(Mono.just(SecurityRuleResult.UNKNOWN)));
    }
}
