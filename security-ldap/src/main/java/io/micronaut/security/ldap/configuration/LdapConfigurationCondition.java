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
package io.micronaut.security.ldap.configuration;

import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.utils.QualifierUtils;
import java.util.Optional;

/**
 * Condition that only creates an {@link LdapConfiguration} for a name under {@value LdapConfiguration#PREFIX}
 * that has nested properties.
 * <p>
 * {@code @EachProperty} binds every key below the prefix as a configuration name, so the documented global switch
 * {@code micronaut.security.ldap.enabled} (or any other single-valued key placed directly under the prefix) would
 * otherwise become an {@link LdapConfiguration} named {@code enabled} with no server, and an
 * {@code LdapAuthenticationProvider} would be created for it.
 *
 * @author Sergio del Amo
 * @since 4.18.2
 */
@Internal
public final class LdapConfigurationCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        Optional<String> name = QualifierUtils.nameQualifier(context.getComponent());
        if (name.isEmpty()) {
            return true;
        }
        BeanContext beanContext = context.getBeanContext();
        if (!(beanContext instanceof PropertyResolver propertyResolver)) {
            return true;
        }
        String prefix = LdapConfiguration.PREFIX + "." + name.get();
        if (propertyResolver.getPropertyEntries(prefix).isEmpty()) {
            context.fail("Property [" + prefix + "] is a single value, not an LDAP configuration");
            return false;
        }
        return true;
    }
}
