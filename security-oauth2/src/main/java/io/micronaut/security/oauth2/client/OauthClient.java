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
package io.micronaut.security.oauth2.client;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;

import java.util.Map;

/**
 * A contract for an OAuth 2.0 client. This interface is the
 * base class necessary for implementing OAuth 2.0 authorization code
 * grant behavior.
 *
 * Given how generic the contract is, any pattern that relies on a redirect and a
 * callback can be implemented with the contract. It could be used
 * for implementing authentication with non standard or non supported
 * standard providers, including OAuth 1.0. Those types of usages
 * are not supported by this API and future major revisions may
 * break their functionality.
 *
 * The client implementations are called through the {@link io.micronaut.security.oauth2.routes.OauthController}.
 * A controller is created for each client bean and routes for the controller
 * are registered in a route builder.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
//tag::clazz[]
public interface OauthClient {

    /**
     * @return The provider name
     */
    String getName();

    /**
     * Responsible for redirecting to the authorization endpoint.
     *
     * @param originating The originating request
     * @return A response publisher
     */
    Publisher<HttpResponse> authorizationRedirect(HttpRequest originating);

    /**
     * Responsible for receiving the authorization callback request and returning
     * an authentication response.
     *
     * @param request The callback request
     * @return The authentication response
     */
    Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request);

}
//end::clazz[]
