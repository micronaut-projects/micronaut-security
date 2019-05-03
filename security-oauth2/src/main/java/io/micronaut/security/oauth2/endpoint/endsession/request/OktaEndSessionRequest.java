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

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.annotation.Nullable;
import java.util.*;

/**
 * Provides specific configuration to logout from Okta.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class OktaEndSessionRequest extends AbstractEndSessionRequest {

    public static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    public static final String PARAM_ID_TOKEN_HINT = "id_token_hint";

    public OktaEndSessionRequest(@Nullable EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                 OauthClientConfiguration clientConfiguration,
                                 OpenIdProviderMetadata providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        return providerMetadata.getEndSessionEndpoint();
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest originating,
                                               Authentication authentication) {
        Map<String, Object> attributes = authentication.getAttributes();
        Map<String, Object> arguments = new HashMap<>();

        if (attributes.containsKey(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY)) {
            arguments.put(PARAM_ID_TOKEN_HINT, attributes.get(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY));
        }

        getRedirectUri(originating).ifPresent(url -> arguments.put(PARAM_POST_LOGOUT_REDIRECT_URI, url));

        return arguments;
    }

}


