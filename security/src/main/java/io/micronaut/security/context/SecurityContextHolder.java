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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.io.service.ServiceDefinition;
import io.micronaut.core.io.service.SoftServiceLoader;

/**
 * Access point for the {@link SecurityContext} associated with the current server request.
 * <p>
 * The returned context is backed by request attributes populated by the security filter.
 *
 * @since 4.18.0
 */
public final class SecurityContextHolder {
    /**
     * The default {@link SecurityContextSupplier} instance.
     */
     public static final SecurityContextSupplier INSTANCE = SoftServiceLoader
            .load(SecurityContextSupplier.class)
            .firstOr("io.micronaut.security.context.ServerRequestContextSecurityContextSupplier", SecurityContextSupplier.class.getClassLoader())
            .map(ServiceDefinition::load)
            .orElse(null);

    private SecurityContextHolder() {
    }

    /**
     * Returns a {@link SecurityContext} for the current request.
     *
     * @return a {@link SecurityContext} backed by the current request, or an empty context if no
     * request is active
     */
    @NonNull
    public static SecurityContext getSecurityContext() {
        return INSTANCE.getSecurityContext();
    }

    /**
     * Clears the security context associated with the current request.
     */
    public static void clearContext() {
        getSecurityContext().clear();
    }
}
