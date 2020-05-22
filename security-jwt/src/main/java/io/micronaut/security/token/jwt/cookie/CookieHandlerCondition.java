/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.handlers.AuthenticationMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Condition used to enable {@link JwtCookieClearerLogoutHandler}.
 * It evaluates to true if micronaut.security.authentication is set to idtoken or cookie.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
public class CookieHandlerCondition implements Condition {
    private static final Logger LOG = LoggerFactory.getLogger(CookieHandlerCondition.class);

    @Override
    public boolean matches(ConditionContext context) {
        PropertyResolver propertyResolver = context.getBeanContext().getBean(PropertyResolver.class);

        final String propertyName = SecurityConfigurationProperties.PREFIX + ".authentication";
        if (!propertyResolver.containsProperty(propertyName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("cookie handler condition is not fulfilled because {} is not set.", propertyName);
            }
            return false;
        }
        Optional<String> propertyValueOptional = propertyResolver.get(propertyName, String.class);
        if (!propertyValueOptional.isPresent()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("cookie handler condition is not fulfilled because {} property is not a String.", propertyName);
            }
            return false;
        }
        final String propertyvalue = propertyValueOptional.get();
        final boolean result = (propertyvalue.equals(AuthenticationMode.COOKIE.toString()) || propertyvalue.equals(AuthenticationMode.IDTOKEN.toString()));
        if (!result) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("cookie handler condition is not fulfilled because {} is not {} or {}.", propertyName,
                        AuthenticationMode.COOKIE.toString(),
                        AuthenticationMode.IDTOKEN.toString());
            }
        }
        return result;
    }
}
