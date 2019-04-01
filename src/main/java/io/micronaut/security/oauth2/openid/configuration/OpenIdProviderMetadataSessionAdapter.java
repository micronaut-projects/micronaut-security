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

package io.micronaut.security.oauth2.openid.configuration;

import io.micronaut.security.oauth2.openid.endpoints.EndpointUrl;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionEndpointConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Creates an {@link OpenIdProviderMetadataSession} by merging together an existing {@link OpenIdProviderMetadataSession}, probably from a
 * fetched from remote identity provider, with the end-session endpoint configuration ({@link EndSessionEndpointConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class OpenIdProviderMetadataSessionAdapter implements OpenIdProviderMetadataSession {

    private final OpenIdProviderMetadataSession openIdProviderMetadataSession;
    private final EndSessionEndpointConfiguration endSessionEndpointConfiguration;

    /**
     *
     * @param openIdProviderMetadataSession Open Id Provider Metadata Session.
     * @param endSessionEndpointConfiguration End-Session Endpoint Configuration
     */
    public OpenIdProviderMetadataSessionAdapter(@Nullable OpenIdProviderMetadataSession openIdProviderMetadataSession,
                                                @Nonnull EndSessionEndpointConfiguration endSessionEndpointConfiguration) {
        this.openIdProviderMetadataSession = openIdProviderMetadataSession;
        this.endSessionEndpointConfiguration = endSessionEndpointConfiguration;
    }

    @Nullable
    @Override
    public String getCheckSessionIframe() {
        return openIdProviderMetadataSession != null ? openIdProviderMetadataSession.getCheckSessionIframe() : null;

    }

    @Nullable
    @Override
    public String getEndSessionEndpoint() {
        return resolveUrl(endSessionEndpointConfiguration, openIdProviderMetadataSession != null ? openIdProviderMetadataSession.getEndSessionEndpoint() : null);
    }

    private String resolveUrl(@Nonnull EndpointUrl endpointUrl, @Nullable String url) {
        return endpointUrl.getUrl() != null ? endpointUrl.getUrl() : url;
    }
}
