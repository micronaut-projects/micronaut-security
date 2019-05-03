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
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationErrorResponseException;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * Provides specific configuration to logout from AWS Cognito.
 *
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html">AWS Cognito Logout Endpoint</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class AwsCognitoEndSessionRequest extends AbstractEndSessionRequest {

    private static final Logger LOG = LoggerFactory.getLogger(AwsCognitoEndSessionRequest.class);

    public static final String PARAM_CLIENT_ID = "client_id";
    public static final String PARAM_LOGOUT_URI = "logout_uri";

    public AwsCognitoEndSessionRequest(@Nullable EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                       OauthClientConfiguration clientConfiguration,
                                       OpenIdProviderMetadata providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        String userInfoEndpoint = providerMetadata.getUserinfoEndpoint();
        if (userInfoEndpoint != null) {
            return UriBuilder.of(providerMetadata.getUserinfoEndpoint()).replacePath("/logout").toString();
        } else {
            URL url = clientConfiguration.getOpenid()
                    .flatMap(OpenIdClientConfiguration::getIssuer)
                    .get();
            return StringUtils.prependUri(url.toString(), "/logout");
        }
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest originating,
                                               Authentication authentication) {
        Map<String, Object> arguments = new HashMap<>();

        arguments.put(PARAM_CLIENT_ID, clientConfiguration.getClientId());

        getRedirectUri(originating).ifPresent(url -> arguments.put(PARAM_LOGOUT_URI, url));

        return arguments;
    }
}


