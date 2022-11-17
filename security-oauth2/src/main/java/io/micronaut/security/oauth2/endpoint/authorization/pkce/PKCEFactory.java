/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;

/**
 * Generates a PKCE parameter.
 *
 * <a href="https://www.rfc-editor.org/rfc/rfc7636.html>Proof Key for Code Exchange by OAuth Public Clients</a>
 * <p>
 *
 * @author Nemanja Mikic
 * @since 3.9.0
 */
@DefaultImplementation(DefaultPKCEFactory.class)
public interface PKCEFactory {

    /**
     * @param request              The original request prior redirect
     * @param response             The authorization redirect response
     * @param authorizationRequest the {@link AuthorizationRequest}
     * @return A pkce parameter. An opaque value used to maintain state between the request and the callback.
     */
    @SuppressWarnings("rawtypes")
    PKCE buildPKCE(HttpRequest<?> request, MutableHttpResponse response, @Nullable AuthorizationRequest authorizationRequest);

}
