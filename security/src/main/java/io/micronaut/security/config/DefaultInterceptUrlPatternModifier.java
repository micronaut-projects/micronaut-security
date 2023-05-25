/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.config;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.context.ServerContextPathProvider;
import jakarta.inject.Singleton;

/**
 * Decorates a {@link }InterceptUrlPattern}. If {@link SecurityConfiguration#isInterceptUrlMapPrependPatternWithContextPath()} is set to true
 * the URL patterns are prepended with the server context path if set.
 * @author Sergio del Amo
 * @since 3.7.3
 */
@Requires(beans = { ServerContextPathProvider.class, SecurityConfiguration.class })
@Singleton
public class DefaultInterceptUrlPatternModifier implements InterceptUrlPatternModifier {

    private final SecurityConfiguration securityConfiguration;
    private final ServerContextPathProvider serverContextPathProvider;

    public DefaultInterceptUrlPatternModifier(SecurityConfiguration securityConfiguration,
                                              ServerContextPathProvider serverContextPathProvider) {
        this.securityConfiguration = securityConfiguration;
        this.serverContextPathProvider = serverContextPathProvider;
    }

    @NonNull
    @Override
    public InterceptUrlMapPattern modify(@NonNull InterceptUrlMapPattern interceptUrlMapPattern) {
        if (securityConfiguration.isInterceptUrlMapPrependPatternWithContextPath()) {
            return new InterceptUrlMapPattern(
                ServerContextPathProviderUtils.prependContextPath(interceptUrlMapPattern.getPattern(), serverContextPathProvider),
                interceptUrlMapPattern.getAccess(),
                interceptUrlMapPattern.getHttpMethod());
        }
        return interceptUrlMapPattern;
    }
}
