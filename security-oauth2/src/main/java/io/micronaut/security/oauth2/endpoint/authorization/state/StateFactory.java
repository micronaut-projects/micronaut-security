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

package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;

import javax.annotation.Nullable;

/**
 * Generates a state parameter.
 *
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Auth Request state parameter</a>
 *
 * state: Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@DefaultImplementation(DefaultStateFactory.class)
public interface StateFactory {

    /**
     * @param request The original request prior redirect
     * @param response The authorization redirect response
     * @param authorizationRequest the {@link AuthorizationRequest}
     * @return A state parameter. An opaque value used to maintain state between the request and the callback.
     */
    @SuppressWarnings("rawtypes")
    String buildState(HttpRequest<?> request, MutableHttpResponse response, @Nullable AuthorizationRequest authorizationRequest);

}
