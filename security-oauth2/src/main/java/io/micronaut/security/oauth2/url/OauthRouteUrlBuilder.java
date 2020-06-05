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
package io.micronaut.security.oauth2.url;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.http.HttpRequest;

import edu.umd.cs.findbugs.annotations.Nullable;
import java.net.URI;
import java.net.URL;

/**
 * Responsible for building URLs to routes the client will receive.
 * requests on.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@DefaultImplementation(DefaultOauthRouteUrlBuilder.class)
public interface OauthRouteUrlBuilder extends AbsoluteUrlBuilder {

    /**
     * Builds the URL to start the OAuth 2.0 authorization code flow.
     *
     * @param originating The originating request
     * @param providerName The oauth provider name
     * @return The URL
     */
    URL buildLoginUrl(@Nullable HttpRequest<?> originating, String providerName);

    /**
     * Builds the URL to receive the OAuth 2.0 authorization callback request.
     *
     * @param originating The originating request
     * @param providerName The oauth provider name
     * @return The URL
     */
    URL buildCallbackUrl(@Nullable HttpRequest<?> originating, String providerName);


    /**
     * Builds the URI to start the OAuth 2.0 authorization code flow.
     *
     * @param providerName The oauth provider name
     * @return The URL
     */
    URI buildLoginUri(String providerName);

    /**
     * Builds the URI to receive the OAuth 2.0 authorization callback request.
     *
     * @param providerName The oauth provider name
     * @return The URL
     */
    URI buildCallbackUri(String providerName);

}
