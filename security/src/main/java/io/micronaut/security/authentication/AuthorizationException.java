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

import javax.annotation.Nullable;

/**
 * Exception thrown when access to a protected resource is denied.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
public class AuthorizationException extends RuntimeException {

    private final Authentication authentication;
    private final boolean forbidden;

    /**
     * @param authentication The authentication that was denied, null if unauthorized
     */
    public AuthorizationException(@Nullable Authentication authentication) {
        this.authentication = authentication;
        this.forbidden = authentication != null;
    }

    /**
     * @return True if the request was authenticated
     */
    public boolean isForbidden() {
        return forbidden;
    }

    /**
     * @return The authentication used in the request
     */
    @Nullable
    public Authentication getAuthentication() {
        return authentication;
    }
}
