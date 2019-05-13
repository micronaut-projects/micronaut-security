/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.context.BeanContext;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties;

import javax.inject.Singleton;

/**
 * Resolves a Bean of type {@link OpenIdTokenResponseValidator} based on configuration.
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class OpenIdTokenResponseValidatorResolver {
    private final BeanContext beanContext;

    /**
     *
     * @param beanContext The Bean Context
     */
    public OpenIdTokenResponseValidatorResolver(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    /**
     *
     * @param clientConfiguration  The client configuration
     * @return a Bean of type {@link OpenIdTokenResponseValidator}.
     */
    public OpenIdTokenResponseValidator getTokenResponseValidator(OauthClientConfiguration clientConfiguration) {
        if (clientConfiguration.getOpenid().isPresent()) {
            return beanContext.getBean(OpenIdTokenResponseValidator.class,
                    Qualifiers.byName(clientConfiguration.getOpenid().get().getTokenValidator()));
        }
        return beanContext.getBean(OpenIdTokenResponseValidator.class,
                Qualifiers.byName(OauthClientConfigurationProperties.OpenIdClientConfigurationProperties.DEFAULT_TOKEN_VALIDATOR));
    }

}
