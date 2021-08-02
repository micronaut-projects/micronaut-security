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
package io.micronaut.security.oauth2.endpoint.token.request.password;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.naming.Named;
import io.micronaut.core.value.ValueResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.grants.GrantType;

import java.util.Optional;

/**
 * Condition to enable the password grant authentication flow for an OAuth provider.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Internal
public class PasswordGrantCondition implements Condition {

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

                    if (clientConfiguration.isEnabled()) {
                        if (clientConfiguration.getGrantType() == GrantType.PASSWORD) {
                            if (clientConfiguration.getToken().isPresent()) {
                                if (beanContext.containsBean(OauthAuthenticationMapper.class, Qualifiers.byName(name))) {
                                    return true;
                                } else {
                                    context.fail("Skipped password grant flow for provider [" + name + "] because no user details mapper could be found");
                                }
                            } else if (clientConfiguration.getOpenid().isPresent()) {
                                boolean hasOpenIdProviderMetadata = beanContext.containsBean(OpenIdProviderMetadata.class, Qualifiers.byName(name));
                                boolean hasTokenResponseValidator = beanContext.containsBean(OpenIdTokenResponseValidator.class);
                                if (hasOpenIdProviderMetadata && hasTokenResponseValidator) {

                                    boolean hasAuthenticationMapper = beanContext.containsBean(OpenIdAuthenticationMapper.class, Qualifiers.byName(name));
                                    if (!hasAuthenticationMapper) {
                                        hasAuthenticationMapper = beanContext.containsBean(DefaultOpenIdAuthenticationMapper.class);
                                    }
                                    if (hasAuthenticationMapper) {
                                        return true;
                                    } else {
                                        context.fail("Skipped password grant flow for provider [" + name + "] because no user details mapper could be found");
                                    }
                                } else {
                                    context.fail("Skipped password grant flow for provider [" + name + "] because no provider metadata and token validator could be found");
                                }
                            } else {
                                context.fail("Skipped password grant flow for provider [" + name + "] because no token endpoint or openid configuration was found");
                            }
                        } else {
                            context.fail("Skipped password grant flow for provider [" + name + "] because the grant type is not 'password'");
                        }
                    } else {
                        context.fail("Skipped password grant flow for provider [" + name + "] because the configuration is disabled");
                    }
                    return false;
                }
            }
        }
        return true;
    }
}
