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
package io.micronaut.security.oauth2.client;

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import jdk.internal.jline.internal.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client for Client Credentials for OAuth 2.0 clients with configure the token endpoint information directly.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
public class DefaultClientCredentialsClient extends AbstractClientCredentialsClient {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultClientCredentialsClient.class);

    /**
     * @param oauthClientConfiguration The client configuration
     * @param tokenEndpointClient      The token endpoint client
     */
    public DefaultClientCredentialsClient(OauthClientConfiguration oauthClientConfiguration, TokenEndpointClient tokenEndpointClient) {
        super(oauthClientConfiguration, tokenEndpointClient);
    }

    @Override
    protected ClientCredentialsTokenRequestContext createTokenRequestContext(@Nullable String scope) {
        return new ClientCredentialsTokenRequestContext(scope, oauthClientConfiguration);
    }
}
