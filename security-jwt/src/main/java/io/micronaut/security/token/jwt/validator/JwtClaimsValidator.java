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
package io.micronaut.security.token.jwt.validator;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.Claims;

/**
 * Provides a contract to create custom JWT claims validations.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 * @param <T> Request
 */
public interface JwtClaimsValidator<T> {

    /**
     * @param claims JWT Claims
     * @param request HTTP request
     * @return whether the JWT claims pass validation.
     */
    boolean validate(@NonNull Claims claims, @Nullable T request);
}
