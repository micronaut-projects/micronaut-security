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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory to create {@link ClientCredentialsTokenPropagator} beans.
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Factory
public class ClientCredentialsTokenPropagatorFactory {
    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsTokenPropagatorFactory.class);

    /**
     * Creates an {@link HttpHeaderClientCredentialsTokenPropagator} for the OAuth 2.0 client if the client-credentials has been configured.
     * @param oauthClientConfiguration The client configuration
     * @return The Client Credentials client
     */
    @EachBean(OauthClientConfiguration.class)
    public ClientCredentialsTokenPropagator createHttpHeaderClientCredentialsPropagator(@Parameter OauthClientConfiguration oauthClientConfiguration) {
        if (!oauthClientConfiguration.getClientCredentials().isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Cannot create a bean of type {} because no client-credentials configuration exists for OAuth 2.0 client {}", ClientCredentialsTokenPropagator.class.getSimpleName(), oauthClientConfiguration.getName());
            }
            return null;
        }
        ClientCredentialsConfiguration clientCredentialsConfiguration = oauthClientConfiguration.getClientCredentials().get();
        if (!clientCredentialsConfiguration.isEnabled()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Cannot create a bean of type {} because client-credentials configuration is disabled for OAuth 2.0 client {}", ClientCredentialsTokenPropagator.class.getSimpleName(), oauthClientConfiguration.getName());
            }
            return null;
        }
        if (clientCredentialsConfiguration.getServiceIdPattern() == null && clientCredentialsConfiguration.getUriPattern() == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Cannot create a bean of type {} because no service-id or uri pattern is defined for the client-credentials configuration of OAuth 2.0 client {}", ClientCredentialsTokenPropagator.class.getSimpleName(), oauthClientConfiguration.getName());
            }
            return null;
        }
        if (clientCredentialsConfiguration.getHeaderPropagation().isPresent()) {
            HttpHeaderClientCredentialsTokenPropagatorConfiguration httpHeaderClientCredentialsTokenPropagatorConfiguration = clientCredentialsConfiguration.getHeaderPropagation().get();
            if (httpHeaderClientCredentialsTokenPropagatorConfiguration.isEnabled()) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Cannot create a bean of type {} because client-credentials.header-propagation is disabled for OAuth 2.0 client {}", ClientCredentialsTokenPropagator.class.getSimpleName(), oauthClientConfiguration.getName());
                }
                return null;
            }
            return new HttpHeaderClientCredentialsTokenPropagator(httpHeaderClientCredentialsTokenPropagatorConfiguration);
        }
        return new HttpHeaderClientCredentialsTokenPropagator(new HttpHeaderClientCredentialsTokenPropagatorConfiguration() {

            @Override
            public String getPrefix() {
                return HttpHeaderClientCredentialsTokenPropagatorConfiguration.DEFAULT_PREFIX;
            }

            @Override
            public String getHeaderName() {
                return HttpHeaderClientCredentialsTokenPropagatorConfiguration.DEFAULT_HEADER_NAME;
            }
        });
    }
}
