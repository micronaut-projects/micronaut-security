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

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import jakarta.inject.Inject;

import java.util.Map;

/**
 * A token request context for sending an authorization
 * code grant request to an OAuth 2.0 provider.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class OauthCodeTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, TokenResponse> {

    private final AuthorizationResponse authorizationResponse;

    @Nullable
    private final String codeVerifier;

    /**
     * @param authorizationResponse The authorization response
     * @param tokenEndpoint         The token endpoint
     * @param clientConfiguration   The client configuration
     * @param codeVerifier         The PKCE code_verifier
     */
    @Inject
    public OauthCodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                        SecureEndpoint tokenEndpoint,
                                        OauthClientConfiguration clientConfiguration,
                                        @Nullable String codeVerifier) {
        super(MediaType.APPLICATION_FORM_URLENCODED_TYPE, tokenEndpoint, clientConfiguration);
        this.authorizationResponse = authorizationResponse;
        this.codeVerifier = codeVerifier;
    }

    /**
     * @param authorizationResponse The authorization response
     * @param tokenEndpoint         The token endpoint
     * @param clientConfiguration   The client configuration
     * @deprecated use {@link OauthCodeTokenRequestContext(AuthorizationResponse, SecureEndpoint, OauthClientConfiguration, String)} instead.
     */
    @Deprecated
    public OauthCodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                        SecureEndpoint tokenEndpoint,
                                        OauthClientConfiguration clientConfiguration) {
        this(authorizationResponse, tokenEndpoint, clientConfiguration, null);
    }

    @Override
    public Map<String, String> getGrant() {
        AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant();
        codeGrant.setCode(authorizationResponse.getCode());
        State state = authorizationResponse.getState();
        codeGrant.setCodeVerifier(getCodeVerifier());
        if (state != null && state.getRedirectUri() != null) {
            codeGrant.setRedirectUri(authorizationResponse.getState().getRedirectUri().toString());
        }
        return codeGrant.toMap();
    }

    @Override
    public Argument<TokenResponse> getResponseType() {
        return Argument.of(TokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(TokenErrorResponse.class);
    }

    /**
     * @since 3.9.0
     * @return The PKCE code verifier
     */
    @Nullable
    public String getCodeVerifier() {
        return codeVerifier;
    }
}
