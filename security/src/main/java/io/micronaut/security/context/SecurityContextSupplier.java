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

/**
 * Supplies the {@link SecurityContext} associated with the current execution.
 *
 * @since 4.18.0
 */
public interface SecurityContextSupplier {
    /**
     * Returns the {@link SecurityContext} associated with the current execution.
     *
     * @return the current {@link SecurityContext}
     */
    @NonNull
    SecurityContext getSecurityContext();
}
