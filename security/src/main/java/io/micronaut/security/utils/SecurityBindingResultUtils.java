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
package io.micronaut.security.utils;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.bind.ArgumentBinder;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.filters.SecurityFilter;

import java.security.Principal;
import java.util.Optional;

import static io.micronaut.core.bind.ArgumentBinder.BindingResult;

/**
 * Security Binding Result Utils.
 */
@Internal
public final class SecurityBindingResultUtils {
    private SecurityBindingResultUtils() {
    }

    public static <A extends Principal> @NonNull ArgumentBinder.BindingResult<A> authentication(@NonNull HttpRequest<?> request,
                                                                                                @NonNull Class<A> authenticationClass) {
        if (!request.getAttributes().contains(SecurityFilter.KEY)) {
            return BindingResult.UNSATISFIED;
        }
        final Optional<A> existing = request.getUserPrincipal(authenticationClass);
        return existing.isPresent() ? (() -> existing) : BindingResult.EMPTY;
    }
}
