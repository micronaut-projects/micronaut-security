/*
 * Copyright 2017-2023 original authors
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

import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger LOG = LoggerFactory.getLogger(AbstractEndSessionRequest.class);
    private static final String PARAMETERS_KEY = "parameters";

    protected final EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder;
    protected final OauthClientConfiguration clientConfiguration;
    protected final Supplier<OpenIdProviderMetadata> providerMetadataSupplier;

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
        this.providerMetadataSupplier = providerMetadata;
    }

    /**
     * Builds the end session URL. Returns {@code null} when {@link #getUrl()} returns {@code null} or an empty string,
     * for example when the OpenID provider metadata does not advertise an {@code end_session_endpoint} and no default
     * can be derived for the provider. Callers treat a {@code null} URL as "no end session redirect available".
     *
     * @param originating The originating request
     * @param authentication The authentication
     * @return The end session URL, or {@code null} if it cannot be determined
     */
    @Nullable
    @Override
    public String getUrl(HttpRequest<?> originating, Authentication authentication) {
        String url = getUrl();
        if (StringUtils.isEmpty(url)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No end session URL could be determined for provider [{}]. The OpenID provider metadata does not contain an end_session_endpoint", clientConfiguration.getName());
            }
            return null;
        }
        return getTemplate(url).expand(getParameters(originating, authentication));
    }

    private Map<String, Object> getParameters(HttpRequest<?> originating, Authentication authentication) {
        return Collections.singletonMap(PARAMETERS_KEY, getArguments(originating, authentication));
    }

    private UriTemplate getTemplate(String url) {
        return UriTemplate.of(url).nest("{?" + PARAMETERS_KEY + "*}");
    }

    /**
     * @return The url of the request, or {@code null} if it cannot be determined (e.g. the provider metadata lacks an {@code end_session_endpoint})
     */
    @Nullable
    protected abstract String getUrl();

    /**
     * @param originating The originating request
     * @param authentication The authentication
     * @return The parameters to include in the URL
     */
    protected abstract Map<String, Object> getArguments(HttpRequest<?> originating, Authentication authentication);

    /**
     * @param originating The originating request
     * @return The absolute redirect URI
     */
    protected String getRedirectUri(HttpRequest<?> originating) {
        return endSessionCallbackUrlBuilder.build(originating).toString();
    }
}
