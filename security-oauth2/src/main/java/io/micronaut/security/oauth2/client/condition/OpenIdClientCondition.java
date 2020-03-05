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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.naming.Named;
import io.micronaut.core.value.ValueResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;
import io.micronaut.security.oauth2.grants.GrantType;

import java.util.Optional;

/**
 * Condition to create an {@link io.micronaut.security.oauth2.client.OpenIdClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Internal
public class OpenIdClientCondition implements Condition {

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
                    OpenIdClientConfiguration openIdClientConfiguration = clientConfiguration.getOpenid().get();

                    if (clientConfiguration.isEnabled()) {

                        if (openIdClientConfiguration.getIssuer().isPresent() || endpointsManuallyConfigured(openIdClientConfiguration)) {
                            if (clientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                                Optional<AuthorizationEndpointConfiguration> authorization = openIdClientConfiguration.getAuthorization();
                                if (!authorization.isPresent() || authorization.get().getResponseType() == ResponseType.CODE) {
                                    return true;
                                } else {
                                    context.fail("Skipped OpenID client creation for provider [" + name + "] because the response type is not 'code'");
                                }
                            } else {
                                context.fail("Skipped OpenID client creation for provider [" + name + "] because the grant type is not 'authorization-code'");
                            }
                        } else {
                            context.fail("Skipped OpenID client creation for provider [" + name + "] because no issuer is configured");
                        }
                    } else {
                        context.fail("Skipped OpenID client creation for provider [" + name + "] because the configuration is disabled");
                    }
                    return false;
                }
            }
        }
        return true;
    }

    private boolean endpointsManuallyConfigured(OpenIdClientConfiguration openIdClientConfiguration) {
        return openIdClientConfiguration.getAuthorization().map(AuthorizationEndpointConfiguration::getUrl).isPresent() &&
                openIdClientConfiguration.getToken().map(TokenEndpointConfiguration::getUrl).isPresent();
    }
}
