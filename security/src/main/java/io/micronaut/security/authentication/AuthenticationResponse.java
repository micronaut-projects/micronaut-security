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
package io.micronaut.security.authentication;

import io.micronaut.core.annotation.NonNull;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * The response of an authentication attempt.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@FunctionalInterface
public interface AuthenticationResponse extends Serializable {

    /**
     * If true, it is expected the {@link #getAuthentication()} method will return
     * a non empty optional.
     *
     * @return true or false depending on whether the user is authenticated
     */
    default boolean isAuthenticated() {
        return getAuthentication().isPresent();
    }

    /**
     * @return The user details if the response is authenticated
     */
    Optional<Authentication> getAuthentication();

    /**
     * @return A message if the response chose to include one
     */
    default Optional<String> getMessage() {
        return Optional.empty();
    }

    /**
     *
     * @param username User's name
     * @return A successful {@link AuthenticationResponse}
     */
    @NonNull
    static AuthenticationResponse success(@NonNull String username) {
        return AuthenticationResponse.success(username, Collections.emptyList(), Collections.emptyMap());
    }

    /**
     *
     * @param username User's name
     * @param roles Users's roles
     * @return A successful {@link AuthenticationResponse}
     */
    @NonNull
    static AuthenticationResponse success(@NonNull String username,
                                          @NonNull Collection<String> roles) {
        return AuthenticationResponse.success(username, roles, Collections.emptyMap());
    }

    /**
     *
     * @param username User's name
     * @param attributes User's attributes
     * @return A successful {@link AuthenticationResponse}
     */
    @NonNull
    static AuthenticationResponse success(@NonNull String username,
                                          @NonNull Map<String, Object> attributes) {
        return () -> Optional.of(Authentication.build(username, Collections.emptyList(), attributes));
    }

    /**
     *
     * @param username User's name
     * @param roles Users's roles
     * @param attributes User's attributes
     * @return A successful {@link AuthenticationResponse}
     */
    @NonNull
    static AuthenticationResponse success(@NonNull String username,
                                          @NonNull Collection<String> roles,
                                          @NonNull Map<String, Object> attributes) {
        return () -> Optional.of(Authentication.build(username, roles, attributes));
    }

    @NonNull
    static AuthenticationResponse failure(@NonNull String message) {
        return new AuthenticationFailed(message);
    }

    @NonNull
    static AuthenticationResponse failure(@NonNull AuthenticationFailureReason reason) {
        return new AuthenticationFailed(reason);
    }

    @NonNull
    static AuthenticationResponse failure() {
        return new AuthenticationFailed();
    }

    @NonNull
    static AuthenticationException exception(@NonNull String message) {
        return new AuthenticationException(new AuthenticationFailed(message));
    }

    @NonNull
    static AuthenticationException exception(@NonNull AuthenticationFailureReason reason) {
        return new AuthenticationException(new AuthenticationFailed(reason));
    }

    @NonNull
    static AuthenticationException exception() {
        return new AuthenticationException(new AuthenticationFailed());
    }
}
