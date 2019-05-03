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
package io.micronaut.security.oauth2.endpoint.endsession.response;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;
import io.micronaut.security.oauth2.url.HostResolver;
import io.micronaut.security.oauth2.url.UrlBuilder;

import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * A {@link UrlBuilder} for generating the URL used by OpenID
 * providers to redirect back to after logging the user out.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class EndSessionCallbackUrlBuilder implements UrlBuilder {

    private final HostResolver hostResolver;
    private final EndSessionConfiguration endSessionConfiguration;

    /**
     * @param hostResolver The host resolver
     * @param endSessionConfiguration The end session configuration
     */
    EndSessionCallbackUrlBuilder(HostResolver hostResolver,
                                 EndSessionConfiguration endSessionConfiguration) {
        this.hostResolver = hostResolver;
        this.endSessionConfiguration = endSessionConfiguration;
    }

    @Override
    public String build(HttpRequest originating, @Nullable String providerName) {
        return UriBuilder.of(hostResolver.resolve(originating))
                .path(getPath(providerName))
                .build()
                .toString();
    }

    @Override
    public String getPath(@Nullable String providerName) {
        return endSessionConfiguration.getRedirectUri();
    }
}
