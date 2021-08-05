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
package io.micronaut.security.ldap;

import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.naming.Named;
import io.micronaut.core.value.ValueResolver;
import io.micronaut.inject.qualifiers.Qualifiers;

import java.util.Optional;

/**
 * Condition to enable the LDAP authentication provider.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Internal
public class LdapEnabledCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();

        if (component instanceof ValueResolver) {
            Optional<String> optional = ((ValueResolver) component).get(Named.class.getName(), String.class);
            if (optional.isPresent()) {
                String name = optional.get();

                LdapConfiguration ldapConfiguration = context.getBean(LdapConfiguration.class, Qualifiers.byName(name));
                return ldapConfiguration.isEnabled();
            }
        }

        return true;
    }
}
