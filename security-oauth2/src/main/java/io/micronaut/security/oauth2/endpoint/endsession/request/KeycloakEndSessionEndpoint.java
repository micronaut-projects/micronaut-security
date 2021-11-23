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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Provides specific configuration to logout from Keycloak.
 *
 * @see <a href="https://github.com/keycloak/keycloak-documentation/blob/master/securing_apps/topics/oidc/java/logout.adoc">Keycloak Logout Endpoint</a>
 *
 * @author Lukas Moravec
 * @since 3.2.0
 */
public class KeycloakEndSessionEndpoint extends AbstractEndSessionRequest {
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String LOGOUT_URI = "/protocol/openid-connect/logout";

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     */
    public KeycloakEndSessionEndpoint(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                      OauthClientConfiguration clientConfiguration,
                                      Supplier<OpenIdProviderMetadata> providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        OpenIdProviderMetadata openIdProviderMetadata = providerMetadataSupplier.get();
        return openIdProviderMetadata.getEndSessionEndpoint() != null ?
                openIdProviderMetadata.getEndSessionEndpoint() :
                StringUtils.prependUri(openIdProviderMetadata.getIssuer(), LOGOUT_URI);
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest<?> originating,
                                               Authentication authentication) {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put(PARAM_REDIRECT_URI, getRedirectUri(originating));
        return arguments;
    }
}
