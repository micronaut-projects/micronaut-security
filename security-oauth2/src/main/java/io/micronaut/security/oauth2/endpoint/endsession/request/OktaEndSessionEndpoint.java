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

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;

import java.util.*;
import java.util.function.Supplier;

/**
 * Provides specific configuration to logout from Okta.
 *
 * @see <a href="https://developer.okta.com/docs/api/resources/oidc/#logout">Okta Logout Endpont</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public class OktaEndSessionEndpoint extends AbstractEndSessionRequest {

    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     */
    public OktaEndSessionEndpoint(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                  OauthClientConfiguration clientConfiguration,
                                  Supplier<OpenIdProviderMetadata> providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        return providerMetadataSupplier.get().getEndSessionEndpoint();
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest<?> originating,
                                               Authentication authentication) {
        Map<String, Object> attributes = authentication.getAttributes();
        Map<String, Object> arguments = new HashMap<>();
        if (attributes.containsKey(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY)) {
            arguments.put(PARAM_ID_TOKEN_HINT, attributes.get(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY));
        }
        arguments.put(PARAM_POST_LOGOUT_REDIRECT_URI, getRedirectUri(originating));
        return arguments;
    }

}


