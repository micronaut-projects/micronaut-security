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

package io.micronaut.security.oauth2.bearer;

import io.micronaut.cache.CacheManager;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Factory;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.grants.GrantType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.List;
import java.util.Optional;

/**
 * Factory that creates token validator for oauth2 based authorization
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
@Factory
public class ClientCredentialsTokenValidatorFactory {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsTokenValidatorFactory.class);

    /**
     * @param introspectedTokenValidators list of handlers that will proceed token introspection metadata.
     * @param configurations              oauth client configuration list. One configuration with CLIENT CREDENTIALS grant
     *                                    type is required in order validator to be created
     * @param cacheManager                cache manager
     * @param beanContext                 bean context
     * @return oauth2 token validator if "client credentials" configuration exists or null
     */
    @Singleton
    public @Nullable ClientCredentialsTokenValidator tokenValidator(List<TokenIntrospectionHandler> introspectedTokenValidators,
                                                                    CacheManager<Object> cacheManager,
                                                                    BeanContext beanContext,
                                                                    List<OauthClientConfiguration> configurations) {
        Optional<OauthClientConfiguration> configuration = getClientCredentialsConfiguration(configurations);

        return configuration.map(clientConfiguration -> new ClientCredentialsTokenValidator(introspectedTokenValidators,
                                                                                            clientConfiguration, cacheManager, beanContext))
                .orElse(null);

    }

    private static Optional<OauthClientConfiguration> getClientCredentialsConfiguration(List<OauthClientConfiguration> clientConfigurations) {
        return clientConfigurations.stream()
                .filter(conf -> conf.getGrantType() == GrantType.CLIENT_CREDENTIALS)
                .findFirst();
    }
}
