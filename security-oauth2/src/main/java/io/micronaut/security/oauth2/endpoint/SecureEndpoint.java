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

import io.micronaut.core.annotation.Nullable;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A contract for an endpoint that requires authentication.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface SecureEndpoint extends Endpoint {

    /**
     * @return An optional list of supported authentication methods
     */
    @Nullable
    Set<String> getAuthenticationMethodsSupported();
}
