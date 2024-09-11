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
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;

import java.util.*;
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
     * @param secureEndpointConfiguration Secure endpoint configuration
     * @param defaultAuthMethod The default authentication method if {@link SecureEndpointConfiguration#getAuthenticationMethod()} is null
     */
    public DefaultSecureEndpoint(@NonNull SecureEndpointConfiguration secureEndpointConfiguration,
                                 @NonNull String defaultAuthMethod) {
        this(secureEndpointConfiguration.getUrl().orElseThrow(() -> new IllegalArgumentException("URL is required")),
                Collections.singleton(secureEndpointConfiguration.getAuthenticationMethod().orElse(defaultAuthMethod)));
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
}
