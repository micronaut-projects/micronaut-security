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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * Base {@link Condition} to enable or disable a CSRF token repository.
 * The canonical configuration key is {@code micronaut.security.csrf.repositories.<name>.enabled}.
 * The legacy key {@code micronaut.security.csrf.repository.<name>.enabled} is still supported but deprecated.
 * When the canonical key is set, it takes precedence. When only the legacy key is set, it is used and a warning is logged once per bean context.
 * When neither key is set, the repository is enabled.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public abstract class CsrfRepositoryEnabledCondition implements Condition {
    private static final Logger LOG = LoggerFactory.getLogger(CsrfRepositoryEnabledCondition.class);
    private static final Map<BeanContext, Set<String>> WARNED = Collections.synchronizedMap(new WeakHashMap<>());

    private final String canonicalKey;
    private final String legacyKey;

    /**
     * @param repositoryName The repository name used in the configuration key. E.g. {@code cookie}.
     */
    protected CsrfRepositoryEnabledCondition(@NonNull String repositoryName) {
        this.canonicalKey = canonicalKey(repositoryName);
        this.legacyKey = legacyKey(repositoryName);
    }

    /**
     * @param repositoryName The repository name
     * @return The canonical configuration key to enable or disable the repository.
     */
    @NonNull
    public static String canonicalKey(@NonNull String repositoryName) {
        return CsrfConfiguration.PREFIX + ".repositories." + repositoryName + ".enabled";
    }

    /**
     * @param repositoryName The repository name
     * @return The deprecated configuration key to enable or disable the repository.
     */
    @NonNull
    public static String legacyKey(@NonNull String repositoryName) {
        return CsrfConfiguration.PREFIX + ".repository." + repositoryName + ".enabled";
    }

    @Override
    public boolean matches(ConditionContext context) {
        Boolean enabled = context.getProperty(canonicalKey, Boolean.class).orElse(null);
        String key = canonicalKey;
        if (enabled == null) {
            enabled = context.getProperty(legacyKey, Boolean.class).orElse(null);
            if (enabled != null) {
                key = legacyKey;
                warnLegacyKey(context.getBeanContext());
            }
        }
        if (enabled == null || enabled) {
            return true;
        }
        context.fail("Property [" + key + "] is set to false");
        return false;
    }

    private void warnLegacyKey(BeanContext beanContext) {
        boolean firstTime;
        synchronized (WARNED) {
            firstTime = WARNED.computeIfAbsent(beanContext, k -> new HashSet<>()).add(legacyKey);
        }
        if (firstTime && LOG.isWarnEnabled()) {
            LOG.warn("Configuration property [{}] is deprecated. Use [{}] instead.", legacyKey, canonicalKey);
        }
    }
}
