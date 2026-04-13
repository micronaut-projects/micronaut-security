/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.context;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;

/**
 * Represents the security state associated with the current execution.
 * <p>
 * A {@link SecurityContext} provides access to the resolved {@link Authentication} and,
 * when applicable, the token that produced it.
 *
 * @since 4.18.0
 */
public interface SecurityContext {

    /**
     * Returns the authentication associated with the current user.
     *
     * @return the current {@link Authentication}, or {@code null} if no user is authenticated
     */
    @Nullable
    Authentication getAuthentication();

    /**
     * Returns the token associated with the current security context.
     *
     * @return the token used to authenticate the current user, or {@code null} if authentication
     * was not token-based or if no user is authenticated
     */
    @Nullable
    String getToken();

    /**
     * Sets the authentication associated with the current security context.
     *
     * @param authentication the authentication to associate, or {@code null} to clear it
     */
    void setAuthentication(@Nullable Authentication authentication);

    /**
     * Sets the token associated with the current security context.
     *
     * @param token the token to associate, or {@code null} to clear it
     */
    void setToken(@Nullable String token);

    /**
     * Sets the rejection status associated with the current security context.
     *
     * @param statusCode the HTTP status code to associate with the current rejection
     */
    void setRejectionStatus(@Nullable Integer statusCode);

    /**
     * Returns the rejection status associated with the current security context.
     *
     * @return the HTTP status code associated with the current rejection, or {@code null}
     */
    @Nullable
    Integer getRejectionStatus();

    /**
     * Clears the current authentication, token, and rejection status.
     */
    void clear();
}
