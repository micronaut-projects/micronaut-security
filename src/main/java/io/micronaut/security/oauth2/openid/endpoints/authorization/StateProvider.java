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

import javax.annotation.Nonnull;

/**
 * Generates a state parameter.
 *
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Auth Request state parameter</a>
 *
 * state: Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface StateProvider {

    /**
     *
      * @return A state parameter. A opaque value used to maintain state between the request and the callback.
     */
    @Nonnull
    String generateState();
}
