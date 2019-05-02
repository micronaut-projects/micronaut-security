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
package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MediaType;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenResponse;
import io.micronaut.security.oauth2.grants.PasswordGrant;

import java.util.Map;

public class OauthPasswordTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, DefaultTokenResponse> {

    private final AuthenticationRequest authenticationRequest;

    public OauthPasswordTokenRequestContext(AuthenticationRequest authenticationRequest,
                                            SecureEndpoint endpoint,
                                            OauthClientConfiguration clientConfiguration) {
        super(MediaType.APPLICATION_FORM_URLENCODED_TYPE, endpoint, clientConfiguration);
        this.authenticationRequest = authenticationRequest;
    }

    @Override
    public Map<String, String> getGrant() {
        PasswordGrant passwordGrant = new PasswordGrant(authenticationRequest, clientConfiguration);
        return passwordGrant.toMap();
    }

    @Override
    public Argument<DefaultTokenResponse> getResponseType() {
        return Argument.of(DefaultTokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(DefaultTokenErrorResponse.class);
    }
}
