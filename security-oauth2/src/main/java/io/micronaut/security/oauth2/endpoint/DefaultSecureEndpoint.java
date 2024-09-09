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
package io.micronaut.security.oauth2.endpoint;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The default implementation of {@link SecureEndpoint}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class DefaultSecureEndpoint implements SecureEndpoint {

    @NonNull
    private final String url;

    @Nullable
    private final Set<String> supportedAuthenticationMethods;

    /**
     * @param url The endpoint URL
     * @param supportedAuthenticationMethods The endpoint authentication methods
     * @deprecated Use {@link DefaultSecureEndpoint#DefaultSecureEndpoint(String, Set)} instead.
     */
    @Deprecated
    public DefaultSecureEndpoint(@NonNull String url,
                                 @Nullable List<AuthenticationMethod> supportedAuthenticationMethods) {
        this.url = url;
        this.supportedAuthenticationMethods = supportedAuthenticationMethods.stream().map(AuthenticationMethod::toString).collect(Collectors.toSet());
    }

    /**
     * @param url The endpoint URL
     * @param supportedAuthenticationMethods The endpoint authentication methods
     */
    public DefaultSecureEndpoint(@NonNull String url,
                                 @Nullable Set<String> supportedAuthenticationMethods) {
        this.url = url;
        this.supportedAuthenticationMethods = supportedAuthenticationMethods;
    }

    @Override
    @NonNull
    public String getUrl() {
        return url;
    }

    @Override
    @Nullable
    public Set<String> getAuthenticationMethodsSupported() {
        return supportedAuthenticationMethods;
    }

    /**
     * @deprecated Use {@link DefaultSecureEndpoint#getAuthenticationMethodsSupported()} instead.
     * @return return the supported authentication methods
     */
    @Deprecated(forRemoval = true)
    @Override
    public Optional<List<AuthenticationMethod>> getSupportedAuthenticationMethods() {
        if (supportedAuthenticationMethods == null) {
            return Optional.empty();
        }
        List<AuthenticationMethod> result  = new ArrayList<>();
        for (String authMethod : supportedAuthenticationMethods) {
            try {
                result.add(AuthenticationMethod.valueOf(authMethod.toUpperCase()));
            } catch (IllegalArgumentException e) {
                // don't crash for non-existing enum options
            }
        }
        return Optional.of(result);
    }
}
