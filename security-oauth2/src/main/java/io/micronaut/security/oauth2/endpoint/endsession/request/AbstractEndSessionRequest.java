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
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public abstract class AbstractEndSessionRequest implements EndSessionRequest {

    public static final String PARAMETERS_KEY = "parameters";

    @Nullable
    protected final EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder;
    protected final OauthClientConfiguration clientConfiguration;
    protected final OpenIdProviderMetadata providerMetadata;

    public AbstractEndSessionRequest(@Nullable EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                     OauthClientConfiguration clientConfiguration,
                                     OpenIdProviderMetadata providerMetadata) {
        this.endSessionCallbackUrlBuilder = endSessionCallbackUrlBuilder;
        this.clientConfiguration = clientConfiguration;
        this.providerMetadata = providerMetadata;
    }

    @Nullable
    @Override
    public String getUrl(HttpRequest originating, Authentication authentication) {
        return getTemplate().expand(getParameters(originating, authentication));
    }

    protected Map<String, Object> getParameters(HttpRequest originating, Authentication authentication) {
        return Collections.singletonMap(PARAMETERS_KEY, getArguments(originating, authentication));
    }

    protected UriTemplate getTemplate() {
        return UriTemplate.of(getUrl()).nest("{?" + PARAMETERS_KEY + "*}");
    }

    protected abstract String getUrl();

    protected abstract Map<String, Object> getArguments(HttpRequest originating, Authentication authentication);

    protected Optional<String> getRedirectUri(HttpRequest originating) {
        return Optional.ofNullable(endSessionCallbackUrlBuilder)
                .map(builder -> builder.build(originating, null));
    }
}
