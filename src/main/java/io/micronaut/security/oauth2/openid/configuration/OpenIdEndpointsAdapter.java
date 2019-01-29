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

package io.micronaut.security.oauth2.openid.configuration;

import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints;

/**
 * Adapts {@link OpenIdProviderMetadata} and {@link OpenIdProviderMetadataSession} to {@link OpenIdEndpoints}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public class OpenIdEndpointsAdapter implements OpenIdEndpoints {

    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final OpenIdProviderMetadataSession openIdProviderMetadataSession;

    /**
     *
     * @param openIdProviderMetadata Open ID Provider metadata
     * @param openIdProviderMetadataSession Open ID Provider Metadata Session
     */
    public OpenIdEndpointsAdapter(OpenIdProviderMetadata openIdProviderMetadata,
                                  OpenIdProviderMetadataSession openIdProviderMetadataSession) {
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.openIdProviderMetadataSession = openIdProviderMetadataSession;
    }

    @Override
    public String getAuthorization() {
        return openIdProviderMetadata.getAuthorizationEndpoint();
    }

    @Override
    public String getEndSession() {
        return openIdProviderMetadataSession.getEndSessionEndpoint();
    }

    @Override
    public String getIntrospection() {
        return openIdProviderMetadata.getIntrospectionEndpoint();
    }

    @Override
    public String getRegistration() {
        return openIdProviderMetadata.getRegistrationEndpoint();
    }

    @Override
    public String getRevocation() {
        return openIdProviderMetadata.getRevocationEndpoint();
    }

    @Override
    public String getToken() {
        return openIdProviderMetadata.getTokenEndpoint();
    }

    @Override
    public String getUserinfo() {
        return openIdProviderMetadata.getUserinfoEndpoint();
    }
}
