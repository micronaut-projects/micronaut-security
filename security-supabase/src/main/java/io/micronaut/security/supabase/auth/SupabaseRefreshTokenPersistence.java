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
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.errors.IssuingAnAccessTokenErrorCode;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * Exchanges a Supabase refresh token for a new session through the {@code refresh_token} grant of
 * {@code POST /token}.
 *
 * <p>Supabase stores and rotates refresh tokens itself, so {@link #persistToken(RefreshTokenGeneratedEvent)}
 * does nothing. {@link #getAuthentication(String)} returns an {@link AuthenticationAccessTokenResponseSchemaAdapter}
 * carrying the rotated tokens, which the login handler writes to the client in place of the ones used to
 * refresh. A refresh token Supabase rejects fails with the OAuth {@code invalid_grant} error.</p>
 *
 * @since 0.0.1
 */
@Experimental
@Requires(beans = SupabaseAuthClient.class)
@Requires(missingBeans = RefreshTokenPersistence.class)
@Singleton
public class SupabaseRefreshTokenPersistence implements RefreshTokenPersistence {
    private final SupabaseTokenGrants grants;
    private final ExecutorService executorService;

    /**
     * Creates the persistence.
     *
     * @param client Supabase Auth client
     * @param executorService Executor the blocking call to Supabase runs on
     */
    public SupabaseRefreshTokenPersistence(SupabaseAuthClient client,
                                           @Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        this.grants = new SupabaseTokenGrants(client);
        this.executorService = executorService;
    }

    @Override
    public void persistToken(RefreshTokenGeneratedEvent event) {
        // Supabase owns the refresh token store.
    }

    @Override
    public Publisher<Authentication> getAuthentication(String refreshToken) {
        return Publishers.fromCompletableFuture(() -> CompletableFuture.supplyAsync(() -> grants.refresh(refreshToken)
            .getAuthentication()
            .orElseThrow(() -> new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_GRANT,
                "Supabase rejected the refresh token", null)), executorService));
    }
}
