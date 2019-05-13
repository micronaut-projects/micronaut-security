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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler;
import io.micronaut.security.oauth2.endpoint.authorization.response.OauthAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.oauth2.grants.GrantType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory to create beans related to the configuration of
 * OAuth 2.0 clients.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Factory
@Internal
public class OauthClientFactory {

    private static final Logger LOG = LoggerFactory.getLogger(OauthClientFactory.class);

    /**
     * Creates an {@link OauthClient} with the provided parameters. Relies
     * on the {@link OauthUserDetailsMapper} to be provided by the user of this
     * library.
     *
     * @param userDetailsMapper The user details mapper
     * @param clientConfiguration The client configuration
     * @param redirectUrlBuilder The redirect url builder
     * @param authorizationResponseHandler The authorization response handler
     * @param beanContext The bean context
     * @return An oauth client
     */
    @EachBean(OauthUserDetailsMapper.class)
    public DefaultOauthClient oauthClient(@Parameter OauthUserDetailsMapper userDetailsMapper,
                                          @Parameter OauthClientConfiguration clientConfiguration,
                                          AuthorizationRedirectHandler redirectUrlBuilder,
                                          OauthAuthorizationResponseHandler authorizationResponseHandler,
                                          BeanContext beanContext) {
        if (clientConfiguration.isEnabled()) {
            if (clientConfiguration.getAuthorization().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                if (clientConfiguration.getToken().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                    if (clientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                        return new DefaultOauthClient(clientConfiguration, userDetailsMapper, redirectUrlBuilder, authorizationResponseHandler, beanContext);
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Skipped client creation for provider [{}] because the grant type is not authorization code", clientConfiguration.getName());
                        }
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Skipped client creation for provider [{}] because no token endpoint is configured", clientConfiguration.getName());
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipped client creation for provider [{}] because no authorization endpoint is configured", clientConfiguration.getName());
                }
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipped client creation for provider [{}] because the configuration is disabled", clientConfiguration.getName());
            }
        }
        return null;
    }
}
