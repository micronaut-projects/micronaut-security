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

import io.micronaut.context.BeanContext;
import io.micronaut.context.BeanRegistration;
import io.micronaut.context.WatchableBeanContext;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.env.DevelopmentMode;
import io.micronaut.context.reload.ClassChangeEvent;
import io.micronaut.context.reload.ReloadStrategy;
import io.micronaut.context.watch.BeanDefinitionChange;
import io.micronaut.context.watch.ConfigurationWatcher;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.reflect.ClassUtils;
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
 *     <li>A class change applied in place that retires a classloader does the same: the filter would hold the
 *     rules and the fetchers of the retired generation.</li>
 *     <li>After the filter is recreated, the development router, when present, rebuilds its routes: a filter route
 *     keeps the filter it first resolved, so requests reach the new filter only through new routes.</li>
 * </ul>
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
@Requires(condition = DevelopmentMode.Active.class)
final class DevelopmentSecurityReloader {

    /**
     * The configuration the rules read when they are created.
     */
    private static final List<String> PREFIXES = List.of(SecurityConfigurationProperties.PREFIX, "endpoints");

    private static final Logger LOG = LoggerFactory.getLogger(DevelopmentSecurityReloader.class);

    private final BeanContext beanContext;

    /**
     * @param beanContext The context, watched when it can be
     */
    DevelopmentSecurityReloader(BeanContext beanContext) {
        this.beanContext = beanContext;
        if (beanContext instanceof WatchableBeanContext watchable) {
            // the first batch is what the filter was, or will be, built from: only what changes after it matters
            watchable.watchDefinitions(SecurityRule.class, null, change -> {
                if (changed(change)) {
                    recreate(false, "security rule definitions changed");
                }
            });
            watchable.watchDefinitions(AuthenticationFetcher.class, null, change -> {
                if (changed(change)) {
                    recreate(false, "authentication fetcher definitions changed");
                }
            });
            for (String prefix : PREFIXES) {
                watchable.watchConfiguration(prefix, change -> recreate(true, "the configuration under " + prefix + " changed"));
            }
            watchable.watchClassChanges(this::onClassChange);
        }
    }

    private static boolean changed(BeanDefinitionChange<?> change) {
        return !change.initial() && (!change.added().isEmpty() || !change.removed().isEmpty());
    }

    private void onClassChange(ClassChangeEvent change) {
        // a restart builds a new context, with new rules and a new filter
        if (change.strategy() != ReloadStrategy.RESTART && !change.retiredLoaders().isEmpty()) {
            recreate(true, "a reload retired a classloader");
        }
    }

    /**
     * Recreates the security rules, when asked, and the security filters the context holds. Nothing is created
     * that was not created already: a bean nobody asked for yet is built from the current definitions and
     * configuration when it is first asked for.
     *
     * @param rules Whether to recreate the rules too
     * @param reason Why, for the log
     * @return {@link ConfigurationWatcher.Outcome#IGNORED} when no such bean was held, {@link ConfigurationWatcher.Outcome#APPLIED}
     * when they were recreated, and {@link ConfigurationWatcher.Outcome#REQUIRES_RESTART} when they were held but kept, as by
     * a context that does not track bean dependencies
     */
    private ConfigurationWatcher.Outcome recreate(boolean rules, String reason) {
        if (!(beanContext instanceof WatchableBeanContext context)) {
            return ConfigurationWatcher.Outcome.IGNORED;
        }
        // taken first: recreating one destroys the beans that received it, as the graph records them
        List<Object> beans = new ArrayList<>();
        if (rules) {
            for (BeanRegistration<SecurityRule> registration : beanContext.getActiveBeanRegistrations(SecurityRule.class)) {
                add(beans, registration.bean());
            }
        }
        boolean filters = false;
        for (BeanRegistration<SecurityFilter> registration : beanContext.getActiveBeanRegistrations(SecurityFilter.class)) {
            add(beans, registration.bean());
            filters = true;
        }
        if (beans.isEmpty()) {
            return ConfigurationWatcher.Outcome.IGNORED;
        }
        LOG.debug("Recreating the security rules and filter: {}", reason);
        boolean recreated = false;
        for (Object bean : beans) {
            // false for a bean destroyed with one recreated before it, and for all of them in a context that does
            // not track bean dependencies: they are kept, and read again after a restart
            recreated |= context.recreate(bean);
        }
        if (filters && recreated) {
            // the filter route of a router keeps the filter it first resolved: only new routes resolve the new one
            DevelopmentRoutes.rebuild(beanContext);
        }
        return recreated ? ConfigurationWatcher.Outcome.APPLIED : ConfigurationWatcher.Outcome.REQUIRES_RESTART;
    }

    private static void add(List<Object> beans, Object bean) {
        for (Object taken : beans) {
            if (taken == bean) {
                return;
            }
        }
        beans.add(bean);
    }

    /**
     * The development router, when the development runtime is on the classpath. The filter routes resolve a filter
     * once and keep it, so a recreated filter serves requests only once the routes are built again, which the
     * development router does in place. Its classes, and the router's, are referenced from this class only, which
     * is loaded once they are known to be present.
     */
    private static final class DevelopmentRoutes {

        private static final String DEV_ROUTER = "io.micronaut.dev.http.DevRouter";

        private DevelopmentRoutes() {
        }

        static void rebuild(BeanContext beanContext) {
            if (!ClassUtils.isPresent(DEV_ROUTER, DevelopmentSecurityReloader.class.getClassLoader())) {
                LOG.debug("No development router: the filter routes keep the previous security filter until the next restart");
                return;
            }
            Holder.rebuild(beanContext);
        }

        private static final class Holder {
            private Holder() {
            }

            static void rebuild(BeanContext beanContext) {
                // only a router already created has routes holding the previous filter
                for (BeanRegistration<io.micronaut.web.router.Router> registration : beanContext.getActiveBeanRegistrations(io.micronaut.web.router.Router.class)) {
                    if (registration.bean() instanceof io.micronaut.dev.http.DevRouter router) {
                        router.rebuild();
                    }
                }
            }
        }
    }
}
