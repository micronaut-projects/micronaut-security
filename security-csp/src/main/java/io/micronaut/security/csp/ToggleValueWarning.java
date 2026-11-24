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

import io.micronaut.context.env.Environment;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PREFIX;

/**
 * Warns at startup about a module, filter or report controller toggle whose value is not a boolean.
 * These toggles are read by an {@link AbstractToggleCondition}, which keeps them enabled for an
 * unknown value on purpose, so that a typo cannot remove the policy; that surprises whoever mistyped
 * {@code false}. Directive settings are checked strictly by {@link BooleanPropertiesCheck}.
 */
@Singleton
@Internal
final class ToggleValueWarning implements ApplicationEventListener<StartupEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(ToggleValueWarning.class);
    /**
     * The toggles read by an {@link AbstractToggleCondition}, which keeps them on for an unknown value.
     */
    private static final List<String> CONDITION_TOGGLES = List.of(CspEnabledCondition.PROPERTY,
        PREFIX + ".filter" + ".enabled", ReportToConfigurationProperties.PREFIX + ".controller" + ".enabled");

    private final Environment environment;

    /**
     * Creates the startup check.
     *
     * @param environment resolves the raw property values
     */
    ToggleValueWarning(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void onApplicationEvent(StartupEvent event) {
        for (String property : CONDITION_TOGGLES) {
            invalidValue(property).ifPresent(value -> LOG.warn("{} is \"{}\", which is not a boolean; it is treated as true, so the "
                + "feature stays enabled. Use true or false.", property, ContentSecurityPolicyUtils.printable(value)));
        }
    }

    private Optional<String> invalidValue(String property) {
        return environment.getProperty(property, String.class)
            .filter(value -> !BooleanPropertiesCheck.BOOLEAN_VALUES.contains(value.trim().toLowerCase(Locale.ROOT)));
    }
}
