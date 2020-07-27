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
package io.micronaut.security.oauth2.endpoint.authorization.state.validation;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.InvalidStateException;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Validates a state parameter.
 *
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Auth Request state parameter</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@DefaultImplementation(DefaultStateValidator.class)
public interface StateValidator {

    /**
     * Validates the provided state.
     *
     * @param request The HTTP Request
     * @param state The state value returned by the authorization server
     * @throws InvalidStateException If the state validation failed
     */
    void validate(@NonNull HttpRequest<?> request, @Nullable State state) throws InvalidStateException;
}
