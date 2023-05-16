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

import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.config.InterceptUrlPatternModifier;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.token.RolesFinder;
import jakarta.inject.Singleton;
import java.util.List;

/**
 * A security rule implementation backed by the {@link SecurityConfiguration#getInterceptUrlMap()}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class ConfigurationInterceptUrlMapRule<T> extends InterceptUrlMapRule<T> {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SensitiveEndpointRule.ORDER - 100;

    private final List<InterceptUrlMapPattern> patternList;

     /**
     *
     * @param rolesFinder Roles Parser
     * @param securityConfiguration The Security Configuration
     * @param interceptUrlPatternModifier InterceptURLMap modifier
     */
    public ConfigurationInterceptUrlMapRule(RolesFinder rolesFinder,
                                            SecurityConfiguration securityConfiguration,
                                            InterceptUrlPatternModifier interceptUrlPatternModifier) {
        super(rolesFinder);
        this.patternList = securityConfiguration.getInterceptUrlMap().stream()
            .map(interceptUrlPatternModifier::modify)
            .toList();
    }

    @Override
    protected List<InterceptUrlMapPattern> getPatternList() {
        return this.patternList;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
