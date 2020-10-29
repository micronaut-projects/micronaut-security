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

import edu.umd.cs.findbugs.annotations.NonNull;
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
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;

import java.util.Optional;

/**
 * Returns true if the OAuth 2.0. Client is enabled, the token endpoint url is not set and an openid issuer is defined.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Internal
public class OpenIdIssuerTokenNotManuallyConfiguredCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();
        BeanContext beanContext = context.getBeanContext();

        if (beanContext instanceof ApplicationContext) {
            if (component instanceof ValueResolver) {
                Optional<String> optional = ((ValueResolver) component).get(Named.class.getName(), String.class);
                if (optional.isPresent()) {
                    String name = optional.get();
                    Optional<String> failure = tokenEndpointIsNotManuallyConfiguredAndItContainsOpenIdIssuer(beanContext, name);
                    if (failure.isPresent()) {
                        context.fail(failure.get());
                        return false;
                    }
                    return true;
                }
            }
        }
        return true;
    }

    /**
     *
     * @param beanContext Bean Context
     * @param name The name qualifier
     * @return Empty if the condition passes or a string containing the failure causing the condition to fail
     */
    public static Optional<String> tokenEndpointIsNotManuallyConfiguredAndItContainsOpenIdIssuer(@NonNull BeanContext beanContext, @NonNull String name) {
        OauthClientConfiguration clientConfiguration = beanContext.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
        if (clientConfiguration.isEnabled()) {
            if (clientConfiguration.getToken().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                return Optional.of("condition failed because for OAuth 2.0 client [" + name + "] because a token endpoint is manually configured");
            } else {
                Optional<OpenIdClientConfiguration> openIdClientConfiguration = clientConfiguration.getOpenid();
                if (openIdClientConfiguration.isPresent()) {
                    if (openIdClientConfiguration.get().getIssuer().isPresent()) {
                        return Optional.empty();
                    } else {
                        return Optional.of("condition failed because for OAuth 2.0 client [" + name + "] because no issuer is configured");
                    }
                } else {
                    return Optional.of("condition failed because for OAuth 2.0 client [" + name + "] because no open id configuration is set");
                }
            }
        } else {
            return Optional.of("condition failed because for OAuth 2.0 client [" + name + "] because the configuration is disabled");
        }
    }
}
