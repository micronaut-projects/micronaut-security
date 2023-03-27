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
package io.micronaut.security.oauth2.client.clientcredentials;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.utils.QualifierUtils;

import java.util.Optional;

/**
 * Condition to determine if the client credentials grant is enabled
 * for a given OAuth 2.0 client.
 *
 * @author James Kleeh
 * @since 2.2.0
 */
@Internal
public class ClientCredentialsEnabled implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();
        Optional<String> nameOptional = QualifierUtils.nameQualifier(component);
        if (nameOptional.isEmpty()) {
            return true;
        }
        String name = nameOptional.get();
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
        String failureMessage = "Client credentials is disabled for the client [" + name + "]";
        if (clientConfiguration.isEnabled()) {
            Optional<ClientCredentialsConfiguration> clientCredentialsConfiguration = clientConfiguration.getClientCredentials();
            if (clientCredentialsConfiguration.isEmpty() || clientCredentialsConfiguration.get().isEnabled()) {
                return true;
            } else {
                context.fail(failureMessage);
                return false;
            }
        } else {
            context.fail(failureMessage);
            return false;
        }

    }
}
