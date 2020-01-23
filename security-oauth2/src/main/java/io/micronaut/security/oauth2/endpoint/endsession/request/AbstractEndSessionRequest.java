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
import java.util.function.Supplier;

/**
 * A base class to extend from to log out of an OpenID provider.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public abstract class AbstractEndSessionRequest implements EndSessionEndpoint {

    private static final String PARAMETERS_KEY = "parameters";

    protected final EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder;
    protected final OauthClientConfiguration clientConfiguration;

    /**
     * @deprecated Use {@link #providerMetadataSupplier} instead.
     */
    @Deprecated
    protected final OpenIdProviderMetadata providerMetadata;
    protected final Supplier<OpenIdProviderMetadata> providerMetadataSupplier;

    /**
     * @deprecated Use {@link #AbstractEndSessionRequest(EndSessionCallbackUrlBuilder, OauthClientConfiguration, Supplier)} instead.
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata
     */
    @Deprecated
    public AbstractEndSessionRequest(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                     OauthClientConfiguration clientConfiguration,
                                     OpenIdProviderMetadata providerMetadata) {
        this(endSessionCallbackUrlBuilder, clientConfiguration, () -> providerMetadata);
    }


    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     */
    public AbstractEndSessionRequest(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                     OauthClientConfiguration clientConfiguration,
                                     Supplier<OpenIdProviderMetadata> providerMetadata) {
        this.endSessionCallbackUrlBuilder = endSessionCallbackUrlBuilder;
        this.clientConfiguration = clientConfiguration;
        this.providerMetadata = null;
        this.providerMetadataSupplier = providerMetadata;
    }

    @Nullable
    @Override
    public String getUrl(HttpRequest originating, Authentication authentication) {
        return getTemplate().expand(getParameters(originating, authentication));
    }

    private Map<String, Object> getParameters(HttpRequest originating, Authentication authentication) {
        return Collections.singletonMap(PARAMETERS_KEY, getArguments(originating, authentication));
    }

    private UriTemplate getTemplate() {
        return UriTemplate.of(getUrl()).nest("{?" + PARAMETERS_KEY + "*}");
    }

    /**
     * @return The url of the request
     */
    protected abstract String getUrl();

    /**
     * @param originating The originating request
     * @param authentication The authentication
     * @return The parameters to include in the URL
     */
    protected abstract Map<String, Object> getArguments(HttpRequest originating, Authentication authentication);

    /**
     * @param originating The originating request
     * @return The absolute redirect URI
     */
    protected String getRedirectUri(HttpRequest originating) {
        return endSessionCallbackUrlBuilder.build(originating).toString();
    }
}
