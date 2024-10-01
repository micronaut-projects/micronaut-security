/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;

import java.util.Optional;

/**
 * Default implementation of {@link SecureEndpointConfiguration}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class DefaultSecureEndpointConfiguration extends DefaultEndpointConfiguration implements SecureEndpointConfiguration {

    private String authenticationMethod = AuthenticationMethods.CLIENT_SECRET_BASIC;

    /**
     * @deprecated Use {@link DefaultSecureEndpointConfiguration#authenticationMethod} instead.
     */
    @Deprecated(forRemoval = true)
    private AuthenticationMethod authMethod = AuthenticationMethod.CLIENT_SECRET_BASIC;

    /**
     * @deprecated Use {@link DefaultSecureEndpointConfiguration#getAuthenticationMethod()} instead.
     */
    @Deprecated(forRemoval = true)
    @Override
    public Optional<AuthenticationMethod> getAuthMethod() {
        return Optional.ofNullable(authMethod);
    }

    /**
     * @deprecated Use {@link DefaultSecureEndpointConfiguration#setAuthenticationMethod(String)} instead.
     * @param authMethod Authentication Method
     */
    @Deprecated(forRemoval = true)
    public void setAuthMethod(@NonNull AuthenticationMethod authMethod) {
        this.authMethod = authMethod;
        this.authenticationMethod = authMethod.toString();
    }

    @Override
    public Optional<String> getAuthenticationMethod() {
        return Optional.ofNullable(authenticationMethod);
    }

    /**
     *
     * @param authenticationMethod Authentication Method
     */
    public void setAuthenticationMethod(String authenticationMethod) {
        try {
            this.authMethod = AuthenticationMethod.valueOf(authenticationMethod.toUpperCase());
        } catch (IllegalArgumentException e) {
        }
        this.authenticationMethod = authenticationMethod;
    }
}
