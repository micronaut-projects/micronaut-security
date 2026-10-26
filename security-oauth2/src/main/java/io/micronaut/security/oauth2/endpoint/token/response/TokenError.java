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
package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.micronaut.core.annotation.Introspected;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Error codes an authorization server may return in an error response.
 *
 * <p>Any error code not modelled here deserializes to {@link #UNKNOWN} instead of failing. The raw error code is
 * available via {@link TokenErrorResponse#getErrorCode()}.</p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 Section 5.2 Token Error Response</a>
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1 Authorization Error Response</a>
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3.1">RFC 6750 Section 3.1 Error Codes</a>
 * @see <a href="https://tools.ietf.org/html/rfc7009#section-2.2.1">RFC 7009 Section 2.2.1 Error Response</a>
 * @see <a href="https://tools.ietf.org/html/rfc8628#section-3.5">RFC 8628 Section 3.5 Device Access Token Response</a>
 */
@Introspected
public enum TokenError {

    /**
     * RFC 6749 Section 5.2.
     */
    INVALID_REQUEST("invalid_request"),

    /**
     * RFC 6749 Section 5.2.
     */
    INVALID_CLIENT("invalid_client"),

    /**
     * RFC 6749 Section 5.2.
     */
    INVALID_GRANT("invalid_grant"),

    /**
     * RFC 6749 Section 5.2.
     */
    UNAUTHORIZED_CLIENT("unauthorized_client"),

    /**
     * RFC 6749 Section 5.2.
     */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),

    /**
     * RFC 6749 Section 5.2.
     */
    INVALID_SCOPE("invalid_scope"),

    /**
     * RFC 6749 Section 4.1.2.1.
     * @since 5.4.0
     */
    ACCESS_DENIED("access_denied"),

    /**
     * RFC 6749 Section 4.1.2.1.
     * @since 5.4.0
     */
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),

    /**
     * RFC 6749 Section 4.1.2.1.
     * @since 5.4.0
     */
    SERVER_ERROR("server_error"),

    /**
     * RFC 6749 Section 4.1.2.1.
     * @since 5.4.0
     */
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),

    /**
     * RFC 6750 Section 3.1.
     * @since 5.4.0
     */
    INVALID_TOKEN("invalid_token"),

    /**
     * RFC 6750 Section 3.1.
     * @since 5.4.0
     */
    INSUFFICIENT_SCOPE("insufficient_scope"),

    /**
     * RFC 7009 Section 2.2.1.
     * @since 5.4.0
     */
    UNSUPPORTED_TOKEN_TYPE("unsupported_token_type"),

    /**
     * RFC 8628 Section 3.5.
     * @since 5.4.0
     */
    AUTHORIZATION_PENDING("authorization_pending"),

    /**
     * RFC 8628 Section 3.5.
     * @since 5.4.0
     */
    SLOW_DOWN("slow_down"),

    /**
     * RFC 8628 Section 3.5.
     * @since 5.4.0
     */
    EXPIRED_TOKEN("expired_token"),

    /**
     * Any error code which is not modelled by this enum. See {@link TokenErrorResponse#getErrorCode()} for the raw value.
     * @since 5.4.0
     */
    UNKNOWN("unknown");

    private final String errorCode;

    /**
     * @param errorCode The error code
     */
    TokenError(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * Resolves a {@link TokenError} from its error code. Unrecognised (or null) codes resolve to {@link #UNKNOWN} instead of throwing.
     *
     * @param errorCode The error code as returned by the authorization server, for example {@code invalid_grant}.
     * @return The matching {@link TokenError} or {@link #UNKNOWN} if no constant matches.
     * @since 5.4.0
     */
    @JsonCreator
    @NonNull
    public static TokenError of(@Nullable String errorCode) {
        if (errorCode == null) {
            return UNKNOWN;
        }
        for (TokenError tokenError : values()) {
            if (tokenError.errorCode.equals(errorCode)) {
                return tokenError;
            }
        }
        for (TokenError tokenError : values()) {
            if (tokenError.errorCode.equalsIgnoreCase(errorCode)) {
                return tokenError;
            }
        }
        return UNKNOWN;
    }

    /**
     * @return The error code, for example {@code invalid_grant}.
     * @since 5.4.0
     */
    @NonNull
    public String getErrorCode() {
        return errorCode;
    }

    /**
     *
     * @return An errorCode code.
     */
    @Override
    @JsonValue
    public String toString() {
        return errorCode;
    }

}
