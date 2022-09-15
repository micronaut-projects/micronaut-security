/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.naming.Named;
import io.micronaut.core.value.ValueResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;

import java.util.Optional;

/**
 * Base class for condition implementations.
 *
 * @author Álvaro Sánchez-Mariscal
 */
@Internal
public abstract class AbstractCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();
        BeanContext beanContext = context.getBeanContext();

        if (beanContext instanceof ApplicationContext && component instanceof ValueResolver) {
            Optional<String> optional = ((ValueResolver) component).get(Named.class.getName(), String.class);
            if (optional.isPresent()) {
                String name = optional.get();

                OauthClientConfiguration clientConfiguration = beanContext.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));

                String failureMsgPrefix = getFailureMessagePrefix(name);
                if (clientConfiguration.isEnabled()) {
                    return handleConfigurationEnabled(clientConfiguration, context, failureMsgPrefix);
                } else {
                    context.fail(failureMsgPrefix + "] because the configuration is disabled");
                }
                return false;
            }
        }
        return true;
    }

    @NonNull
    protected abstract String getFailureMessagePrefix(@NonNull String name);

    protected abstract boolean handleConfigurationEnabled(@NonNull OauthClientConfiguration clientConfiguration,
                                                          @NonNull ConditionContext<?> context,
                                                          @NonNull String failureMsgPrefix);

}
