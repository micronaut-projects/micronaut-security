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
package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.ClientCredentialsGrant;

import java.util.Map;

/**
 * A token request context for sending a client credentials request to an OAuth 2.0 provider.
 *
 * @author Sergio del Amo
 * @version 2.1.0
 */
public class ClientCredentialsTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, TokenResponse> {
    private final ClientCredentialsGrant grant;

    /**
     * @param scope requested scopes
     * @param tokenEndpoint The token endpoint
     * @param clientConfiguration The client configuration
     */
    public ClientCredentialsTokenRequestContext(String scope,
                                                SecureEndpoint tokenEndpoint,
                                                OauthClientConfiguration clientConfiguration) {
        super(MediaType.APPLICATION_FORM_URLENCODED_TYPE, tokenEndpoint, clientConfiguration);
        ClientCredentialsGrant grant = new ClientCredentialsGrant();
        grant.setScope(scope);
        grant.setAudience(clientConfiguration.getAudience());
        this.grant = grant;
    }

    /**
     * @param clientConfiguration The client configuration
     */
    public ClientCredentialsTokenRequestContext(OauthClientConfiguration clientConfiguration) {
        super(MediaType.APPLICATION_FORM_URLENCODED_TYPE, clientConfiguration.getTokenEndpoint(), clientConfiguration);
        this.grant = new ClientCredentialsGrant();
        this.grant.setAudience(clientConfiguration.getAudience());
    }

    /**
     * @param scope requested scopes
     * @param clientConfiguration The client configuration
     */
    public ClientCredentialsTokenRequestContext(String scope, OauthClientConfiguration clientConfiguration) {
        super(MediaType.APPLICATION_FORM_URLENCODED_TYPE, clientConfiguration.getTokenEndpoint(), clientConfiguration);
        this.grant = new ClientCredentialsGrant();
        this.grant.setScope(scope);
        this.grant.setAudience(clientConfiguration.getAudience());
    }

    @Override
    public Map<String, String> getGrant() {
        return grant.toMap();
    }

    @Override
    public Argument<TokenResponse> getResponseType() {
        return Argument.of(TokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(TokenErrorResponse.class);
    }
}
