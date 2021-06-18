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
package io.micronaut.security.oauth2.client.clientcredentials;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Client for Client Credentials for OAuth 2.0 clients which user open id configuration.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
public class DefaultClientCredentialsOpenIdClient extends AbstractClientCredentialsClient {

    private final Supplier<OpenIdProviderMetadata> openIdProviderMetadata;
    private final Supplier<SecureEndpoint> tokenEndpoint;

    /**
     * @param oauthClientConfiguration The client configuration
     * @param tokenEndpointClient      The token endpoint client
     * @param openIdProviderMetadata The provider metadata
     */
    public DefaultClientCredentialsOpenIdClient(@NonNull OauthClientConfiguration oauthClientConfiguration,
                                                @NonNull TokenEndpointClient tokenEndpointClient,
                                                Supplier<OpenIdProviderMetadata> openIdProviderMetadata) {
        super(oauthClientConfiguration, tokenEndpointClient);
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.tokenEndpoint = SupplierUtil.memoized(this::getTokenEndpoint);
    }

    @Override
    protected ClientCredentialsTokenRequestContext createTokenRequestContext(String scope) {
        return new ClientCredentialsTokenRequestContext(scope, tokenEndpoint.get(), oauthClientConfiguration);
    }

    /**
     *
     * @return The Token endpoint using the information in the open id provider metadata
     */
    protected SecureEndpoint getTokenEndpoint() {
        Optional<List<AuthenticationMethod>> authMethodsSupported = openIdProviderMetadata.get().getTokenEndpointAuthMethods();
        return new DefaultSecureEndpoint(openIdProviderMetadata.get().getTokenEndpoint(), authMethodsSupported.orElse(null));
    }
}
