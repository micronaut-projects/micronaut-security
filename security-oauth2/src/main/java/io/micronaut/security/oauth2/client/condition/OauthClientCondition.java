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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.grants.GrantType;

/**
 * Condition to create an {@link io.micronaut.security.oauth2.client.OauthClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Internal
public class OauthClientCondition extends AbstractCondition {

    @Override
    @NonNull
    protected String getFailureMessagePrefix(@NonNull final String name) {
        return "Skipped client creation for provider [" + name;
    }

    @Override
    protected boolean handleConfigurationEnabled(@NonNull final OauthClientConfiguration clientConfiguration,
                                                 @NonNull final ConditionContext<?> context,
                                                 @NonNull final String failureMsgPrefix) {
        if (clientConfiguration.getAuthorization().flatMap(EndpointConfiguration::getUrl).isPresent()) {
            if (clientConfiguration.getToken().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                if (clientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                    return true;
                } else {
                    context.fail(failureMsgPrefix + "] because grant type is not authorization code");
                }
            } else {
                context.fail(failureMsgPrefix + "] because no token endpoint is configured");
            }
        } else {
            context.fail(failureMsgPrefix + "] because no authorization endpoint is configured");
        }
        return false;
    }
}
