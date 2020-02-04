/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.filters;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Requires;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Ensures the security filter runs after the session filter (if present) and the metrics filter (if present)
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(missingBeans = SecurityFilterOrderProvider.class)
@Singleton
public class SessionSecurityFilterOrderProvider implements SecurityFilterOrderProvider {

    private static final Integer ORDER = 100;
    private final BeanContext beanContext;

    /**
     * Default constructor. Added for backward compatibility.
     */
    public SessionSecurityFilterOrderProvider() {
        this.beanContext = null;
    }

    /**
     * Injected constructor.
     *
     * @param beanContext The bean context
     */
    @Inject
    public SessionSecurityFilterOrderProvider(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    @Override
    public int getOrder() {
        if (beanContext == null) {
            return ORDER;
        }

        boolean configurationPresent = Stream.of("io.micronaut.configuration.metrics.micrometer", "io.micronaut.session")
                .map(beanContext::findBeanConfiguration)
                .anyMatch(Optional::isPresent);

        if (configurationPresent) {
            return ORDER;
        } else {
            return 0;
        }
    }
}
