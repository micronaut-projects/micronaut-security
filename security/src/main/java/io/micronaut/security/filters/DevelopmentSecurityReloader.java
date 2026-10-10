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
package io.micronaut.security.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.BeanRegistration;
import io.micronaut.context.WatchableBeanContext;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.env.DevelopmentActive;
import io.micronaut.context.reload.ClassChangeEvent;
import io.micronaut.context.reload.ReloadStrategy;
import io.micronaut.context.watch.BeanDefinitionChange;
import io.micronaut.context.watch.ReloadingConfigurationWatcher;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.rules.SecurityRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Recreates the security rules and the security filter in development mode when what they were built from
 * changes. It exists only in development mode, so nothing of it is on the path of a request.
 *
 * <ul>
 *     <li>A {@link SecurityRule} or {@link AuthenticationFetcher} definition registered or removed recreates the
 *     {@link SecurityFilter}, which collects the rules and the fetchers once, when it is created.</li>
 *     <li>A change of the configuration under {@code micronaut.security} or {@code endpoints} recreates the
 *     security rules, which read the intercept-url map, the IP patterns and the endpoint sensitivity when they are
 *     created, and the filter that holds them.</li>
 *     <li>A class change applied in place that retires a classloader recreates the rules, the authentication
 *     fetchers and the filter: they would hold, and run, classes of the retired generation.</li>
 *     <li>A change of the configuration that enables or disables the security filter asks for a restart: it adds or
 *     removes a filter route, which recreating beans cannot do.</li>
 * </ul>
 *
 * <p>A filter route resolves its filter once and keeps it. In development mode the router builds its routes again
 * when a server filter bean is destroyed, so the next request reaches the recreated filter.</p>
 *
 * <p>Each bean is recreated through {@link WatchableBeanContext#recreate(Object)}, which destroys the beans that
 * received it, as the dependency graph of a development context records. A context that does not track bean
 * dependencies recreates nothing: the beans are kept, rather than replaced under the beans that received them,
 * and the change is seen after a restart, which a configuration change asks the development runtime for.</p>
 *
 * <p>It holds the context only, never a security bean: a bean that received one is a dependent of it, which
 * recreating it would destroy along with its watches.</p>
 *
 * @author graemerocher
 * @since 5.5.0
 */
@Internal
@Context
@DevelopmentActive
final class DevelopmentSecurityReloader {

    /**
     * The configuration the rules read when they are created.
     */
    private static final List<String> PREFIXES = List.of(SecurityConfigurationProperties.PREFIX, "endpoints");

    /**
     * The properties that decide whether the security filter exists at all.
     */
    private static final List<String> FILTER_ENABLED = List.of(SecurityConfigurationProperties.PREFIX + ".enabled", SecurityFilterConfigurationProperties.PREFIX + ".enabled");

    private static final Logger LOG = LoggerFactory.getLogger(DevelopmentSecurityReloader.class);

    private final BeanContext beanContext;

    /**
     * Whether the security filter was enabled when this context was built: the routes have a filter route only if so.
     */
    private final boolean filterEnabled;

    /**
     * @param beanContext The context, watched when it can be
     */
    DevelopmentSecurityReloader(BeanContext beanContext) {
        this.beanContext = beanContext;
        this.filterEnabled = filterEnabled();
        if (beanContext instanceof WatchableBeanContext watchable) {
            // the first batch is what the filter was, or will be, built from: only what changes after it matters
            watchable.definitions(SecurityRule.class).watch(change -> {
                if (changed(change)) {
                    recreate(false, false, "security rule definitions changed");
                }
            });
            watchable.definitions(AuthenticationFetcher.class).watch(change -> {
                if (changed(change)) {
                    recreate(false, false, "authentication fetcher definitions changed");
                }
            });
            for (String prefix : PREFIXES) {
                watchable.configuration(prefix).watchReloading(change -> onConfigurationChange(prefix));
            }
            watchable.classChanges().watch(this::onClassChange);
        }
    }

    private ReloadingConfigurationWatcher.Outcome onConfigurationChange(String prefix) {
        if (filterEnabled() != filterEnabled) {
            // a filter enabled or disabled adds or removes a filter route, and a filter bean that is not there is
            // neither destroyed nor recreated: only a new context has the routes the configuration now asks for
            LOG.debug("The security filter was enabled or disabled: a restart applies it");
            return ReloadingConfigurationWatcher.Outcome.REQUIRES_RESTART;
        }
        return recreate(true, false, "the configuration under " + prefix + " changed");
    }

    private boolean filterEnabled() {
        if (!(beanContext instanceof ApplicationContext context)) {
            return true;
        }
        for (String property : FILTER_ENABLED) {
            if (!context.getEnvironment().getProperty(property, Boolean.class).orElse(true)) {
                return false;
            }
        }
        return true;
    }

    private static boolean changed(BeanDefinitionChange<?> change) {
        return !change.initial() && (!change.added().isEmpty() || !change.removed().isEmpty());
    }

    private void onClassChange(ClassChangeEvent change) {
        // a restart builds a new context, with new rules and a new filter
        if (change.strategy() != ReloadStrategy.RESTART && !change.retiredLoaders().isEmpty()) {
            recreate(true, true, "a reload retired a classloader");
        }
    }

    /**
     * Recreates the security rules and the authentication fetchers, when asked, and the security filters the context holds. Nothing is created
     * that was not created already: a bean nobody asked for yet is built from the current definitions and
     * configuration when it is first asked for.
     *
     * @param rules Whether to recreate the rules too
     * @param fetchers Whether to recreate the authentication fetchers too
     * @param reason Why, for the log
     * @return {@link ReloadingConfigurationWatcher.Outcome#IGNORED} when no such bean was held, {@link ReloadingConfigurationWatcher.Outcome#APPLIED}
     * when they were recreated, and {@link ReloadingConfigurationWatcher.Outcome#REQUIRES_RESTART} when they were held but kept, as by
     * a context that does not track bean dependencies
     */
    private ReloadingConfigurationWatcher.Outcome recreate(boolean rules, boolean fetchers, String reason) {
        if (!(beanContext instanceof WatchableBeanContext context)) {
            return ReloadingConfigurationWatcher.Outcome.IGNORED;
        }
        // taken first: recreating one destroys the beans that received it, as the graph records them
        List<Object> beans = new ArrayList<>();
        if (rules) {
            for (BeanRegistration<SecurityRule> registration : beanContext.getActiveBeanRegistrations(SecurityRule.class)) {
                add(beans, registration.bean());
            }
        }
        if (fetchers) {
            for (BeanRegistration<AuthenticationFetcher> registration : beanContext.getActiveBeanRegistrations(AuthenticationFetcher.class)) {
                add(beans, registration.bean());
            }
        }
        for (BeanRegistration<SecurityFilter> registration : beanContext.getActiveBeanRegistrations(SecurityFilter.class)) {
            add(beans, registration.bean());
        }
        if (beans.isEmpty()) {
            return ReloadingConfigurationWatcher.Outcome.IGNORED;
        }
        LOG.debug("Recreating the security rules and filter: {}", reason);
        boolean recreated = false;
        for (Object bean : beans) {
            // false for a bean destroyed with one recreated before it, and for all of them in a context that does
            // not track bean dependencies: they are kept, and read again after a restart
            recreated |= context.recreate(bean);
        }
        return recreated ? ReloadingConfigurationWatcher.Outcome.APPLIED : ReloadingConfigurationWatcher.Outcome.REQUIRES_RESTART;
    }

    private static void add(List<Object> beans, Object bean) {
        for (Object taken : beans) {
            if (taken == bean) {
                return;
            }
        }
        beans.add(bean);
    }
}
