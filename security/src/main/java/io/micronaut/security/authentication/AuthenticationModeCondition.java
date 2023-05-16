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
package io.micronaut.security.authentication;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.config.SecurityConfigurationProperties;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A condition that matches a supplied list of authentication modes.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
public abstract class AuthenticationModeCondition implements Condition {

    private final List<AuthenticationMode> acceptableModes;

    public AuthenticationModeCondition(List<AuthenticationMode> acceptableModes) {
        this.acceptableModes = acceptableModes;
    }

    @Override
    public boolean matches(ConditionContext context) {
        PropertyResolver propertyResolver = context.getBeanContext().getBean(PropertyResolver.class);

        final String propertyName = SecurityConfigurationProperties.PREFIX + ".authentication";
        if (!propertyResolver.containsProperty(propertyName)) {
            if (AuthenticationModeConditionLogging.LOG.isDebugEnabled()) {
                AuthenticationModeConditionLogging.LOG.debug("{}} is not fulfilled because {} is not set.", getClass().getSimpleName(), propertyName);
            }
            return false;
        }
        Optional<String> propertyValueOptional = propertyResolver.get(propertyName, String.class);
        if (propertyValueOptional.isPresent()) {
            final String propertyvalue = propertyValueOptional.get();
            final boolean result = acceptableModes.stream().map(AuthenticationMode::toString).anyMatch(propertyvalue::equals);
            if (!result && AuthenticationModeConditionLogging.LOG.isDebugEnabled()) {
                AuthenticationModeConditionLogging.LOG.debug("{} is not fulfilled because {} is not one of {}.", getClass().getSimpleName(), propertyName, acceptableModes);
            }
            return result;
        } else {
            if (AuthenticationModeConditionLogging.LOG.isDebugEnabled()) {
                AuthenticationModeConditionLogging.LOG.debug("{} is not fulfilled because {} property is not a String.", getClass().getSimpleName(), propertyName);
            }
            return false;
        }
    }

    // GraalVM support: Use an inner class for logging to avoid build time initialization of logger
    private static final class AuthenticationModeConditionLogging {
        private static final Logger LOG = LoggerFactory.getLogger(AuthenticationModeCondition.class);
    }
}
