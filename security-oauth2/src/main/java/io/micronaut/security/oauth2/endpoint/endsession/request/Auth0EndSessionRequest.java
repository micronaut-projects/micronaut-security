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

package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;

import java.net.URL;
import java.util.*;

/**
 * Provides specific configuration to logout from Auth0.
 *
 * @see <a href="https://auth0.com/docs/logout/guides/logout-auth0">Log Users Out of Auth0</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public class Auth0EndSessionRequest extends AbstractEndSessionRequest {

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata
     */
    public Auth0EndSessionRequest(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                  OauthClientConfiguration clientConfiguration,
                                  OpenIdProviderMetadata providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        URL url = clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getIssuer)
                .get();
        return StringUtils.prependUri(url.toString(), "/v2/logout");
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest originating,
                                               Authentication authentication) {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("client_id", clientConfiguration.getClientId());
        arguments.put("returnTo", getRedirectUri(originating));
        return arguments;
    }
}


