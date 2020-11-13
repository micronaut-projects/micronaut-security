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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.condition.OauthClientTokenManuallyConfiguredCondition;
import io.micronaut.security.oauth2.client.condition.OpenIdIssuerTokenNotManuallyConfiguredCondition;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;

import javax.inject.Provider;
import java.util.function.Supplier;

/**
 * Factory to create {@link ClientCredentialsClient} beans.
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Factory
public class ClientCredentialsFactory {
    /**
     * Creates an {@link ClientCredentialsClient} from the provided parameters.
     * @param oauthClientConfiguration The client configuration
     * @param tokenEndpointClient Token endpoint client
     * @param openIdProviderMetadata The open id provider metadata
     * @return The Client Credentials client
     */
    @EachBean(OpenIdClientConfiguration.class)
    DefaultClientCredentialsOpenIdClient clientCredentialsOpenIdClient(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                                                       TokenEndpointClient tokenEndpointClient,
                                                                       @Parameter Provider<DefaultOpenIdProviderMetadata> openIdProviderMetadata) {
        if (oauthClientConfiguration.getClientCredentials().isPresent() &&
                !oauthClientConfiguration.getClientCredentials().get().isEnabled()) {
            return null;
        }
        Supplier<OpenIdProviderMetadata> metadataSupplier = SupplierUtil.memoized(openIdProviderMetadata::get);
        return new DefaultClientCredentialsOpenIdClient(oauthClientConfiguration.getName(), oauthClientConfiguration, tokenEndpointClient, metadataSupplier);
    }

    /**
     * Creates an {@link ClientCredentialsClient} for an OAuth 2.0 Client.
     *
     * @param oauthClientConfiguration The open id provider metadata
     * @param tokenEndpointClient Token endpoint client
     * @return The Client Credentials client
     */
    @Requires(condition = OauthClientTokenManuallyConfiguredCondition.class)
    @EachBean(OauthClientConfiguration.class)
    DefaultClientCredentialsClient clientCredentialsClient(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                                           TokenEndpointClient tokenEndpointClient) {
        if (oauthClientConfiguration.getClientCredentials().isPresent() &&
                !oauthClientConfiguration.getClientCredentials().get().isEnabled()) {
            return null;
        }
        return new DefaultClientCredentialsClient(oauthClientConfiguration.getName(), oauthClientConfiguration, tokenEndpointClient);
    }
}
