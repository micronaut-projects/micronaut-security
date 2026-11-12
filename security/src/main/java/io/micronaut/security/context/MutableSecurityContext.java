/*
 * Copyright 2017-2026 original authors
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

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Mutable {@link SecurityContext} implementation for non-request execution contexts.
 */
@Internal
final class MutableSecurityContext implements SecurityContext {
    @Nullable
    private Authentication authentication;

    @Nullable
    private String token;

    @Nullable
    private Integer rejectionStatus;

    @Override
    @Nullable
    public Authentication getAuthentication() {
        return authentication;
    }

    @Override
    @Nullable
    public String getToken() {
        return token;
    }

    @Override
    @NonNull
    public SecurityContext withAuthentication(@Nullable Authentication authentication) {
        this.authentication = authentication;
        return this;
    }

    @Override
    @NonNull
    public SecurityContext withToken(@Nullable String token) {
        this.token = token;
        return this;
    }

    @Override
    @NonNull
    public SecurityContext withRejectionStatus(@Nullable Integer statusCode) {
        this.rejectionStatus = statusCode;
        return this;
    }

    @Override
    @Nullable
    public Integer getRejectionStatus() {
        return rejectionStatus;
    }

    @Override
    public void clear() {
        rejectionStatus = null;
        token = null;
        authentication = null;
    }
}
