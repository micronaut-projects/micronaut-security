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
import io.micronaut.http.HttpResponse;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;

import java.util.Optional;

/**
 * Handles a log out request that redirects to an OpenID provider
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface EndSessionController {

    /**
     * Performs and end session redirect to an OpenID provider.
     *
     * @param request The current request
     * @param authentication The current authentication
     * @return A redirecting http response
     */
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Executable
    Optional<HttpResponse> endSession(HttpRequest request, Authentication authentication);
}
