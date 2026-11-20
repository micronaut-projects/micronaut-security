/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.runtime.context.scope.refresh.RefreshEvent;
import io.micronaut.runtime.context.scope.refresh.RefreshEventListener;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import jakarta.inject.Singleton;

import java.util.Set;

/**
 * Rebuilds the cached directives of {@link DefaultContentSecurityPolicyGenerator} when the
 * {@code micronaut.security.csp} configuration is refreshed. The configuration beans are re-bound in
 * place by the refresh scope, which runs before this listener, so the generator reads the new values.
 */
@Requires(beans = DefaultContentSecurityPolicyGenerator.class)
@Singleton
@Internal
final class ContentSecurityPolicyGeneratorRefreshListener implements RefreshEventListener {
    private final DefaultContentSecurityPolicyGenerator generator;

    /**
     * Creates the listener.
     *
     * @param generator the generator whose cached directives are rebuilt
     */
    ContentSecurityPolicyGeneratorRefreshListener(DefaultContentSecurityPolicyGenerator generator) {
        this.generator = generator;
    }

    @Override
    public Set<String> getObservedConfigurationPrefixes() {
        return Set.of(ContentSecurityPolicyConfigurationProperties.PREFIX);
    }

    @Override
    public void onApplicationEvent(RefreshEvent event) {
        generator.refresh();
    }
}
