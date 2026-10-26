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
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.config.InterceptUrlPatternModifier;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.token.RolesFinder;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A security rule implementation backed by the {@link SecurityConfiguration#getInterceptUrlMap()}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class ConfigurationInterceptUrlMapRule extends InterceptUrlMapRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SensitiveEndpointRule.ORDER - 100;

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
    @Deprecated
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
     * @since 3.11.3
     */
    @Inject
    public ConfigurationInterceptUrlMapRule(RolesFinder rolesFinder,
                                            SecurityConfiguration securityConfiguration,
                                            InterceptUrlPatternModifier interceptUrlPatternModifier,
                                            @Nullable ServerContextPathProvider serverContextPathProvider) {
        super(rolesFinder);
        this.patternList = securityConfiguration.getInterceptUrlMap().stream()
            .map(interceptUrlPatternModifier::modify)
            .collect(Collectors.toList());
        this.contextPath = normalizeContextPath(serverContextPathProvider);
    }

    /**
     *
     * @param rolesFinder Roles Parser
     * @param securityConfiguration The Security Configuration
     * @deprecated Use {@link #ConfigurationInterceptUrlMapRule(RolesFinder, SecurityConfiguration, InterceptUrlPatternModifier, ServerContextPathProvider)} instead.
     */
    @Deprecated
    public ConfigurationInterceptUrlMapRule(RolesFinder rolesFinder,
                                            SecurityConfiguration securityConfiguration) {
        this(rolesFinder, securityConfiguration, interceptUrlMapPattern -> interceptUrlMapPattern, null);
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
     * {@code /context/} (what the root pattern {@code /} becomes once the context path is prepended) and
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
        String normalized = StringUtils.trimLeadingCharacter(contextPath, '/');
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return StringUtils.isEmpty(normalized) ? null : "/" + normalized;
    }
}
