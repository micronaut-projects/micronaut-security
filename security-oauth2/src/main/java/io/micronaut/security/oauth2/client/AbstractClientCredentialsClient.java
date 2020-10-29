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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract class to create a Client for client credentials grant.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
public abstract class AbstractClientCredentialsClient implements ClientCredentialsClient {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractClientCredentialsClient.class);

    protected final TokenEndpointClient tokenEndpointClient;
    protected final OauthClientConfiguration oauthClientConfiguration;

    /**
     * @param tokenEndpointClient The token endpoint client
     * @param oauthClientConfiguration The client configuration
     */
    public AbstractClientCredentialsClient(OauthClientConfiguration oauthClientConfiguration,
                                          TokenEndpointClient tokenEndpointClient) {
        this.oauthClientConfiguration = oauthClientConfiguration;
        this.tokenEndpointClient = tokenEndpointClient;
    }

    @NonNull
    @Override
    public Publisher<TokenResponse> clientCredentials(@Nullable String scope) {
        ClientCredentialsTokenRequestContext context = createTokenRequestContext(scope);
        return tokenEndpointClient.sendRequest(context);
    }

    protected abstract ClientCredentialsTokenRequestContext createTokenRequestContext(@Nullable String scope);
}
