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
package io.micronaut.security.oauth2.client.clientcredentials.propagation;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.naming.Named;
import io.micronaut.core.value.ValueResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;

import java.util.Optional;

/**
 *
 */
@Internal
public class ClientCredentialsHeaderPropagatorEnabled implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();
        BeanContext beanContext = context.getBeanContext();

        if (beanContext instanceof ApplicationContext) {
            if (component instanceof ValueResolver) {
                Optional<String> optional = ((ValueResolver) component).get(Named.class.getName(), String.class);
                if (optional.isPresent()) {
                    String name = optional.get();
                    OauthClientConfiguration clientConfiguration = beanContext.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
                    Optional<ClientCredentialsHeaderTokenPropagatorConfiguration> headerTokenConfiguration = clientConfiguration.getClientCredentials()
                            .flatMap(ClientCredentialsConfiguration::getHeaderPropagation);
                    if (headerTokenConfiguration.isPresent()) {
                        if (headerTokenConfiguration.get().isEnabled()) {
                            return true;
                        } else {
                            context.fail("Client credentials header token handler is disabled");
                            return false;
                        }
                    } else {
                        context.fail("Client credentials header token handler disabled due to a lack of configuration");
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
