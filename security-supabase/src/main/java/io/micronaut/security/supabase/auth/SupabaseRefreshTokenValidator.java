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
package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;

import java.util.Optional;

/**
 * Accepts any non-blank refresh token, since Supabase refresh tokens are opaque strings that only Supabase can
 * validate. Revocation and reuse are detected by {@link SupabaseRefreshTokenPersistence} when the token is
 * exchanged.
 *
 * @since 0.0.1
 */
@Experimental
@Requires(beans = SupabaseAuthClient.class)
@Requires(missingBeans = RefreshTokenValidator.class)
@Singleton
public class SupabaseRefreshTokenValidator implements RefreshTokenValidator {

    /**
     * Creates the validator.
     */
    public SupabaseRefreshTokenValidator() {
    }

    @Override
    @NonNull
    public Optional<String> validate(@NonNull String refreshToken) {
        return StringUtils.isNotEmpty(refreshToken) ? Optional.of(refreshToken) : Optional.empty();
    }
}
