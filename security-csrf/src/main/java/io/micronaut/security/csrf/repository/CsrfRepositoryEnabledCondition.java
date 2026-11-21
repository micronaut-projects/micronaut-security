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
package io.micronaut.security.csrf.repository;

import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csrf.CsrfConfiguration;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Base {@link Condition} to enable or disable a CSRF token repository.
 * The canonical configuration key is {@code micronaut.security.csrf.repositories.<name>.enabled}.
 * The legacy key {@code micronaut.security.csrf.repository.<name>.enabled} is still supported but deprecated.
 * When the canonical key is set, it takes precedence. When only the legacy key is set, it is used.
 * Whenever the legacy key is set, a warning is logged once per bean context.
 * When neither key is set, the repository is enabled.
 *
 * @author Sergio del Amo
 * @since 5.5.3
 */
@Internal
public abstract class CsrfRepositoryEnabledCondition implements Condition {
    private static final Map<BeanContext, Set<String>> WARNED = Collections.synchronizedMap(new WeakHashMap<>());

    private final String canonicalKey;
    private final String legacyKey;

    /**
     * @param repositoryName The repository name used in the configuration key. E.g. {@code cookie}.
     */
    protected CsrfRepositoryEnabledCondition(@NonNull String repositoryName) {
        this.canonicalKey = CsrfConfiguration.PREFIX + ".repositories." + repositoryName + ".enabled";
        this.legacyKey = CsrfConfiguration.PREFIX + ".repository." + repositoryName + ".enabled";
    }

    @Override
    public boolean matches(ConditionContext context) {
        Boolean canonical = context.getProperty(canonicalKey, Boolean.class).orElse(null);
        Boolean legacy = context.getProperty(legacyKey, Boolean.class).orElse(null);
        if (legacy != null) {
            warnLegacyKey(context.getBeanContext(), canonical != null);
        }
        Boolean enabled = canonical != null ? canonical : legacy;
        String key = canonical != null ? canonicalKey : legacyKey;
        if (enabled == null || enabled) {
            return true;
        }
        String value = context.getProperty(key, String.class).orElse(null);
        context.fail("Property [" + key + "] is set to [" + value + "], which disables the repository. Only true, yes, y or on enable it.");
        return false;
    }

    private void warnLegacyKey(BeanContext beanContext, boolean canonicalKeySet) {
        // one condition instance serves every bean context, and lookups of a disabled bean evaluate it again
        boolean firstTime = WARNED.computeIfAbsent(beanContext, k -> ConcurrentHashMap.newKeySet()).add(legacyKey);
        if (!firstTime || !CsrfRepositoryEnabledConditionLogging.LOG.isWarnEnabled()) {
            return;
        }
        if (canonicalKeySet) {
            CsrfRepositoryEnabledConditionLogging.LOG.warn("Configuration property [{}] is deprecated and ignored because [{}] is set. Remove it.", legacyKey, canonicalKey);
        } else {
            CsrfRepositoryEnabledConditionLogging.LOG.warn("Configuration property [{}] is deprecated. Use [{}] instead.", legacyKey, canonicalKey);
        }
    }

    // GraalVM support: Use an inner class for logging to avoid build time initialization of logger
    private static final class CsrfRepositoryEnabledConditionLogging {
        private static final Logger LOG = LoggerFactory.getLogger(CsrfRepositoryEnabledCondition.class);
    }
}
