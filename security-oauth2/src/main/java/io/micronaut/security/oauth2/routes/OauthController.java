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
package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.Executable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.rules.SecurityRule;
import org.reactivestreams.Publisher;

import java.util.Map;

/**
 * Responsible for OAuth 2.0 authorization redirect, authorization
 * callback, and end session redirects. Each controller is
 * associated with a single {@link OauthClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Secured(SecurityRule.IS_ANONYMOUS)
public interface OauthController {

    /**
     * @return The client associated with this controller
     */
    OauthClient getClient();

    /**
     * Performs an authorization redirect to an OAuth 2.0 provider.
     *
     * @param request The current request
     * @return A redirecting http response
     */
    @Executable
    Publisher<MutableHttpResponse<?>> login(HttpRequest<?> request);

    /**
     * Receives the authorization callback from the OAuth 2.0 provider
     * and responds to the user.
     *
     * @param request The current request
     * @return A response
     */
    @Executable
    Publisher<MutableHttpResponse<?>> callback(HttpRequest<Map<String, Object>> request);

}
