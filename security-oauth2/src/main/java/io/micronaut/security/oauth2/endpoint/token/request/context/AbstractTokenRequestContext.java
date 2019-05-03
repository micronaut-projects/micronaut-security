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

import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;

public abstract class AbstractTokenRequestContext<G, R extends TokenResponse> implements TokenRequestContext<G, R> {

    protected final MediaType mediaType;
    protected final SecureEndpoint endpoint;
    protected final OauthClientConfiguration clientConfiguration;

    public AbstractTokenRequestContext(MediaType mediaType,
                                       SecureEndpoint endpoint,
                                       OauthClientConfiguration clientConfiguration) {

        this.mediaType = mediaType;
        this.endpoint = endpoint;
        this.clientConfiguration = clientConfiguration;
    }

    @Override
    public MediaType getMediaType() {
        return mediaType;
    }

    @Override
    public SecureEndpoint getEndpoint() {
        return endpoint;
    }

    @Override
    public OauthClientConfiguration getClientConfiguration() {
        return clientConfiguration;
    }
}
