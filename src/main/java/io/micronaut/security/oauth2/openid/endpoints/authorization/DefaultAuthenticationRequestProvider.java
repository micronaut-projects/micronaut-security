/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * Default implementation of {@link AuthenticationRequestProvider}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = {OauthConfiguration.class, AuthorizationEndpointRequestConfiguration.class})
@Singleton
public class DefaultAuthenticationRequestProvider implements AuthenticationRequestProvider {

    @Nonnull
    private final OauthConfiguration oauthConfiguration;

    @Nonnull
    private final AuthorizationEndpointRequestConfiguration authorizationEndpointRequestConfiguration;

    @Nullable
    private final StateProvider stateProvider;

    @Nullable
    private final NonceProvider nonceProvider;

    @Nullable
    private final LoginHintProvider loginHintProvider;

    @Nullable
    private final IdTokenHintProvider idTokenHintProvider;

    /**
     *
     * @param oauthConfiguration Oauth 2.0 Configuration
     * @param authorizationEndpointRequestConfiguration Authorization Endpoint Request Configuration
     * @param stateProvider Authorization state provider
     * @param nonceProvider Authorization nonce provider
     * @param loginHintProvider Login Hint Provider
     * @param idTokenHintProvider Id Token Hint Provider
     */
    public DefaultAuthenticationRequestProvider(OauthConfiguration oauthConfiguration,
                                                AuthorizationEndpointRequestConfiguration authorizationEndpointRequestConfiguration,
                                                @Nullable StateProvider stateProvider,
                                                @Nullable NonceProvider nonceProvider,
                                                @Nullable LoginHintProvider loginHintProvider,
                                                @Nullable IdTokenHintProvider idTokenHintProvider) {
        this.oauthConfiguration = oauthConfiguration;
        this.authorizationEndpointRequestConfiguration = authorizationEndpointRequestConfiguration;
        this.stateProvider = stateProvider;
        this.nonceProvider = nonceProvider;
        this.loginHintProvider = loginHintProvider;
        this.idTokenHintProvider = idTokenHintProvider;
    }

    @Override
    public AuthenticationRequest generateAuthenticationRequest() {
        return new AuthenticationRequestAdapter(oauthConfiguration,
                authorizationEndpointRequestConfiguration,
                stateProvider,
                nonceProvider,
                loginHintProvider,
                idTokenHintProvider);
    }
}
