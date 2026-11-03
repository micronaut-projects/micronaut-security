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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.supabase.auth.AccessTokenResponseSchema;
import io.micronaut.supabase.auth.ErrorSchema;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import io.micronaut.supabase.auth.SupabaseAuthRequests.TokenRequest;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Exchanges credentials for a Supabase session through {@code POST /token} and adapts the outcome to Micronaut
 * Security types.
 *
 * @since 0.0.1
 */
@Experimental
@Internal
final class SupabaseTokenGrants {
    /**
     * {@code grant_type} of the password grant.
     */
    static final String GRANT_TYPE_PASSWORD = "password";

    /**
     * {@code grant_type} of the refresh-token grant.
     */
    static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    private static final Logger LOG = LoggerFactory.getLogger(SupabaseTokenGrants.class);

    private final SupabaseAuthClient client;

    SupabaseTokenGrants(SupabaseAuthClient client) {
        this.client = client;
    }

    /**
     * Signs in with an email address or phone number and a password.
     *
     * @param identity Email address, or phone number in E.164 format
     * @param password Password
     * @return The authenticated session, or a failure describing why Supabase rejected the credentials
     */
    @NonNull
    AuthenticationResponse password(@NonNull String identity, @NonNull String password) {
        boolean email = identity.contains("@");
        TokenRequest request = new TokenRequest(null, password, email ? identity : null, email ? null : identity,
            null, null, null, null, null, null, null, null, null, null, null, null);
        return grant(GRANT_TYPE_PASSWORD, request);
    }

    /**
     * Exchanges a refresh token for a new session. Supabase rotates the refresh token on every use.
     *
     * @param refreshToken Refresh token
     * @return The refreshed session, or a failure if the refresh token was revoked, reused or never existed
     */
    @NonNull
    AuthenticationResponse refresh(@NonNull String refreshToken) {
        TokenRequest request = new TokenRequest(refreshToken, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null);
        return grant(GRANT_TYPE_REFRESH_TOKEN, request);
    }

    @NonNull
    private AuthenticationResponse grant(@NonNull String grantType, @NonNull TokenRequest request) {
        HttpResponse<AccessTokenResponseSchema> response;
        try {
            response = client.token(grantType, request);
        } catch (HttpClientResponseException e) {
            return failure(e.getResponse().getBody(ErrorSchema.class).orElse(null), e.getStatus().getCode());
        }
        if (response.getStatus().getCode() >= 400) {
            return failure(response.getBody(ErrorSchema.class).orElse(null), response.getStatus().getCode());
        }
        AccessTokenResponseSchema body = response.body();
        if (body == null || StringUtils.isEmpty(body.accessToken())) {
            LOG.debug("Supabase {} grant answered {} without an access token", grantType, response.getStatus());
            return AuthenticationResponse.failure();
        }
        try {
            AuthenticationAccessTokenResponseSchemaAdapter authentication = new AuthenticationAccessTokenResponseSchemaAdapter(body);
            return () -> Optional.of(authentication);
        } catch (IllegalArgumentException e) {
            LOG.debug("Supabase {} grant answered without a user: {}", grantType, e.getMessage());
            return AuthenticationResponse.failure();
        }
    }

    @NonNull
    private static AuthenticationResponse failure(@Nullable ErrorSchema error, int status) {
        String code = error == null ? null : (error.errorCode() != null ? error.errorCode() : error.error());
        LOG.debug("Supabase token grant rejected with status {} and error code {}", status, code);
        AuthenticationFailureReason reason = failureReason(code);
        if (reason != AuthenticationFailureReason.UNKNOWN) {
            return AuthenticationResponse.failure(reason);
        }
        String message = error == null ? null : (error.msg() != null ? error.msg() : error.errorDescription());
        return message == null ? AuthenticationResponse.failure() : AuthenticationResponse.failure(message);
    }

    /**
     * Maps a Supabase Auth error code to a Micronaut Security failure reason.
     *
     * @param errorCode Supabase Auth {@code error_code}, or the OAuth {@code error} when absent
     * @return The failure reason; {@link AuthenticationFailureReason#UNKNOWN} for codes without a counterpart
     */
    @NonNull
    static AuthenticationFailureReason failureReason(@Nullable String errorCode) {
        if (errorCode == null) {
            return AuthenticationFailureReason.UNKNOWN;
        }
        return switch (errorCode) {
            case "invalid_credentials", "invalid_grant" -> AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH;
            case "user_not_found" -> AuthenticationFailureReason.USER_NOT_FOUND;
            case "email_not_confirmed", "phone_not_confirmed" -> AuthenticationFailureReason.USER_DISABLED;
            case "user_banned" -> AuthenticationFailureReason.ACCOUNT_LOCKED;
            default -> AuthenticationFailureReason.UNKNOWN;
        };
    }
}
