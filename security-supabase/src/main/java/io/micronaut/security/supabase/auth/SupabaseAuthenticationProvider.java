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
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates users against Supabase Auth with the password grant of {@code POST /token}.
 *
 * <p>The identity is sent as the {@code email} when it contains {@code @}, and as the {@code phone} otherwise.
 * A successful sign-in yields an {@link AuthenticationAccessTokenResponseSchemaAdapter}, so the login handler
 * hands the Supabase access and refresh tokens to the client instead of generating its own. Supabase error codes
 * map to {@link AuthenticationFailureReason} where one exists.</p>
 *
 * <p>The provider calls Supabase with the blocking HTTP client and therefore runs on the
 * {@link io.micronaut.scheduling.TaskExecutors#BLOCKING} executor.</p>
 *
 * @param <B> Request body type
 * @since 0.0.1
 */
@Experimental
@Requires(classes = HttpRequest.class)
@Requires(beans = SupabaseAuthClient.class)
@Singleton
public class SupabaseAuthenticationProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
    private final SupabaseTokenGrants grants;

    /**
     * Creates the provider.
     *
     * @param client Supabase Auth client
     */
    public SupabaseAuthenticationProvider(SupabaseAuthClient client) {
        this.grants = new SupabaseTokenGrants(client);
    }

    @Override
    @NonNull
    public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                               @NonNull AuthenticationRequest<String, String> authRequest) {
        String identity = authRequest.getIdentity();
        String secret = authRequest.getSecret();
        if (StringUtils.isEmpty(identity) || StringUtils.isEmpty(secret)) {
            return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }
        return grants.password(identity, secret);
    }
}
