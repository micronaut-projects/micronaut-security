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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.config.InterceptUrlPatternModifier;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.token.RolesFinder;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A security rule implementation backed by the {@link SecurityConfiguration#getInterceptUrlMap()}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = HttpRequest.class)
@Requires(beans = { RolesFinder.class, SecurityConfiguration.class, InterceptUrlPatternModifier.class })
@Singleton
public class ConfigurationInterceptUrlMapRule extends InterceptUrlMapRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = -100;

    private final List<InterceptUrlMapPattern> patternList;

    @Nullable
    private final String contextPath;

    /**
     *
     * @param rolesFinder Roles Parser
     * @param securityConfiguration The Security Configuration
     * @param interceptUrlPatternModifier InterceptURLMap modifier
     * @deprecated Use {@link #ConfigurationInterceptUrlMapRule(RolesFinder, SecurityConfiguration, InterceptUrlPatternModifier, ServerContextPathProvider)} instead.
     */
    @Deprecated(forRemoval = true, since = "5.5.2")
    public ConfigurationInterceptUrlMapRule(RolesFinder rolesFinder,
                                            SecurityConfiguration securityConfiguration,
                                            InterceptUrlPatternModifier interceptUrlPatternModifier) {
        this(rolesFinder, securityConfiguration, interceptUrlPatternModifier, null);
    }

    /**
     *
     * @param rolesFinder Roles Parser
     * @param securityConfiguration The Security Configuration
     * @param interceptUrlPatternModifier InterceptURLMap modifier
     * @param serverContextPathProvider Server context path provider
     * @since 5.5.2
     */
    @Inject
    public ConfigurationInterceptUrlMapRule(RolesFinder rolesFinder,
                                            SecurityConfiguration securityConfiguration,
                                            InterceptUrlPatternModifier interceptUrlPatternModifier,
                                            @Nullable ServerContextPathProvider serverContextPathProvider) {
        super(rolesFinder);
        this.patternList = securityConfiguration.getInterceptUrlMap().stream()
            .map(interceptUrlPatternModifier::modify)
            .toList();
        this.contextPath = normalizeContextPath(serverContextPathProvider);
    }

    @Override
    protected List<InterceptUrlMapPattern> getPatternList() {
        return this.patternList;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Requests for the context root ({@code /context} or {@code /context/}) are the application's root route. They
     * are matched as the root path {@code /} is matched when no context path is set, so that patterns such as
     * {@code /context/*} apply to them.
     */
    @Override
    protected boolean matchesPath(@NonNull String pattern, @NonNull String path) {
        if (super.matchesPath(pattern, path)) {
            return true;
        }
        return contextPath != null && contextPath.equals(path) && super.matchesPath(pattern, path + "/");
    }

    @Nullable
    private static String normalizeContextPath(@Nullable ServerContextPathProvider serverContextPathProvider) {
        if (serverContextPathProvider == null) {
            return null;
        }
        String contextPath = serverContextPathProvider.getContextPath();
        if (StringUtils.isEmpty(contextPath)) {
            return null;
        }
        String normalized = StringUtils.trimTrailingCharacter(StringUtils.trimLeadingCharacter(contextPath, '/'), '/');
        return StringUtils.isEmpty(normalized) ? null : "/" + normalized;
    }

    /**
     * Whether the first configured pattern that applies to the request allows anonymous access.
     *
     * @param request The current request
     * @return Whether authentication resolution can be skipped for the request
     * @since 5.4.0
     */
    @Internal
    public boolean isAnonymous(HttpRequest<?> request) {
        return findPattern(request)
            .map(pattern -> pattern.getAccess().contains(SecurityRule.IS_ANONYMOUS))
            .orElse(false);
    }
}
