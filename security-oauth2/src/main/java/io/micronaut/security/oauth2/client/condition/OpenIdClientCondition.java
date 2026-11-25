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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;
import io.micronaut.security.oauth2.endpoint.authorization.response.DefaultOpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.utils.QualifierUtils;

import java.util.Collection;
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
        Optional<String> nameOptional = QualifierUtils.nameQualifier(component);
        if (nameOptional.isEmpty()) {
            return true;
        }
        String name = nameOptional.get();
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
        String failureMessagePrefix = "Skipped OpenID client creation for provider [" + name;
        if (clientConfiguration.isEnabled()) {
            Optional<OpenIdClientConfiguration> openid = clientConfiguration.getOpenid();
            if (openid.isPresent()) {
                OpenIdClientConfiguration openIdClientConfiguration = openid.get();
                if (openIdClientConfiguration.getIssuer().isPresent() || endpointsManuallyConfigured(openIdClientConfiguration)) {
                    if (clientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                        Optional<AuthorizationEndpointConfiguration> authorization = openIdClientConfiguration.getAuthorization();
                        if (!authorization.isPresent() || authorization.get().getResponseType() == ResponseType.CODE) {
                            if (!usesDefaultAuthorizationResponseHandler(context) || hasAuthenticationMapper(context, name)) {
                                return true;
                            } else {
                                context.fail(failureMessagePrefix + "] because no OpenIdAuthenticationMapper bean named [" + name + "] and no global OpenIdAuthenticationMapper bean without a qualifier could be found");
                            }
                        } else {
                            context.fail(failureMessagePrefix + "] because the response type is not 'code'");
                        }
                    } else {
                        context.fail(failureMessagePrefix + "] because the grant type is not 'authorization-code'");
                    }
                } else {
                    context.fail(failureMessagePrefix  + "] because no issuer is configured");
                }
            }
        } else {
            context.fail(failureMessagePrefix + "] because the configuration is disabled");
        }
        return false;

    }

    /**
     * Only the {@link DefaultOpenIdAuthorizationResponseHandler#handle} implementation maps the ID token with an
     * {@link OpenIdAuthenticationMapper}, and it rejects the authorization response itself when it has none. A custom
     * {@link OpenIdAuthorizationResponseHandler} receives a nullable mapper and may authenticate without one; so may
     * a subclass of the default handler which overrides {@code handle}. The mapper requirement therefore applies
     * only when the registered handler is the default handler itself, not a subclass of it.
     */
    private static boolean usesDefaultAuthorizationResponseHandler(ConditionContext<?> context) {
        Collection<BeanDefinition<OpenIdAuthorizationResponseHandler>> handlers = context.getBeanContext().getBeanDefinitions(OpenIdAuthorizationResponseHandler.class);
        return !handlers.isEmpty() && handlers.stream().allMatch(handler -> DefaultOpenIdAuthorizationResponseHandler.class.equals(handler.getBeanType()));
    }

    /**
     * A client maps the ID token with the {@link OpenIdAuthenticationMapper} registered under its name, or with the
     * global mapper: the one without a qualifier. A mapper registered for another client never qualifies.
     */
    private static boolean hasAuthenticationMapper(ConditionContext<?> context, String name) {
        return context.getBeanContext().containsBean(OpenIdAuthenticationMapper.class, Qualifiers.byName(name))
            || context.getBeanContext().containsBean(OpenIdAuthenticationMapper.class, Qualifiers.none());
    }

    private boolean endpointsManuallyConfigured(OpenIdClientConfiguration openIdClientConfiguration) {
        return openIdClientConfiguration.getAuthorization().map(AuthorizationEndpointConfiguration::getUrl).isPresent() &&
            openIdClientConfiguration.getToken().map(TokenEndpointConfiguration::getUrl).isPresent();
    }
}
