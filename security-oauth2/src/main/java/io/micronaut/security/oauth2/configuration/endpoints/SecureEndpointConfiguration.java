/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;

import java.util.Optional;

/**
 * Configuration extension of {@link EndpointConfiguration} for endpoints which require authentication.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface SecureEndpointConfiguration extends EndpointConfiguration {

    /**
     *
     * @return An optional Authentication Method.
     */
    Optional<AuthenticationMethod> getAuthMethod();
}
