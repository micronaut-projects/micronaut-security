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
package io.micronaut.supabase.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;
import java.util.List;

/**
 * Error body returned by Supabase Auth for a rejected request.
 *
 * <p>Two shapes exist. OAuth-style errors carry {@code error} and {@code errorDescription}; all other
 * errors carry {@code code}, {@code msg} and a stable {@code errorCode} such as {@code weak_password} or
 * {@code user_already_exists}. Branch on {@code errorCode} rather than on {@code msg}, whose wording may
 * change.</p>
 *
 * @param error OAuth 2.0 error identifier such as {@code invalid_request}, {@code access_denied} or
 *              {@code server_error}
 * @param errorDescription Human-readable description accompanying {@code error}
 * @param code HTTP status code; usually absent when {@code error} is present
 * @param msg Human-readable message describing the problem; usually absent when {@code error} is present
 * @param errorCode Stable machine-readable code identifying the class of error
 * @param weakPassword Present only for {@code POST /signup} when the password is too weak
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ErrorSchema(
    @Nullable String error,
    @JsonProperty("error_description") @Nullable String errorDescription,
    @Nullable Integer code,
    @Nullable String msg,
    @JsonProperty("error_code") @Nullable String errorCode,
    @JsonProperty("weak_password") @Nullable WeakPassword weakPassword
) {
    /**
     * Details of a password rejected by the project's password policy.
     *
     * @param reasons Policy violations, such as {@code length}, {@code characters} or {@code pwned}
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record WeakPassword(
        @Nullable List<String> reasons
    ) {
    }
}
