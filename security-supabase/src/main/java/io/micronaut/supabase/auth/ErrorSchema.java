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
 * Models the ErrorSchema object in Supabase Auth.
 *
 * @param error Certain responses will contain this property with the provided values.  Usually one of these:   -
 *     invalid_request   - unauthorized_client   - access_denied   - server_error   -
 *     temporarily_unavailable   - unsupported_otp_type
 * @param errorDescription Certain responses that have an `error` property may have this property which describes the error.
 * @param code The HTTP status code. Usually missing if `error` is present.
 * @param msg A basic message describing the problem with the request. Usually missing if `error` is present.
 * @param errorCode A short code used to describe the class of error encountered.
 * @param weakPassword Only returned on the `/signup` endpoint if the password used is too weak. Inspect the `reasons`
 *     and `msg` property to identify the causes.
 * @since 5.5.1
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
     * Only returned on the `/signup` endpoint if the password used is too weak. Inspect the `reasons` and `msg`
     * property to identify the causes.
     *
     * @param reasons The value for {@code reasons}.
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record WeakPassword(
        @Nullable List<String> reasons
    ) {
    }
}
