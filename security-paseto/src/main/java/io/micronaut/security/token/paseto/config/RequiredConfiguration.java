/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.config;

import io.micronaut.core.annotation.Nullable;
import java.time.Instant;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Encapsulates required configuration.
 * @author Sergio del Amo
 * @since 3.2.0
 */
public interface RequiredConfiguration {
    @Nullable
    default String getRequiredAudience() {
        return null;
    }

    @Nullable
    default String getRequiredKeyId() {
        return null;
    }

    @Nullable
    default String getRequiredIssuer() {
        return null;
    }

    @Nullable
    default String getRequiredSubject() {
        return null;
    }

    @Nullable
    default String getRequiredTokenId() {
        return null;
    }

    @Nullable
    default Instant getRequiredExpiration() {
        return null;
    }

    @Nullable
    default Instant getRequiredIssuedAt() {
        return null;
    }

    @Nullable
    default Instant getRequiredNotBefore() {
        return null;
    }

    @Nullable
    default Map<String, Predicate<Object>> getRequiredClaimsPredicate() {
        return null;
    }

    @Nullable
    default Map<String, Object> getRequiredClaimsValue() {
        return null;
    }

    @Nullable
    default Map<String, Predicate<Object>> getRequiredFooterPredicate() {
        return null;
    }
}
