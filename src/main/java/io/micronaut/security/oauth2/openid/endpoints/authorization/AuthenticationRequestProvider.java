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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import io.micronaut.http.HttpRequest;

/**
 * Provides an authentication Request.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface AuthenticationRequestProvider {

    /**
     * @param request the Original request prior redirect.
     * @param unauthorized If the reason for redirection is because the user
     *                     requested a resource that requires authorization.
     * @return An Authentication request against an Open ID identity provider.
     */
    AuthenticationRequest generateAuthenticationRequest(HttpRequest<?> request, boolean unauthorized);
}
