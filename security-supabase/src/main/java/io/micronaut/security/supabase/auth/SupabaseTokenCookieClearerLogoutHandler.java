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

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import io.micronaut.security.token.cookie.TokenCookieClearerLogoutHandler;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.concurrent.ExecutorService;

/**
 * Clears the token cookies and revokes the Supabase session they belonged to.
 *
 * <p>Replaces {@link TokenCookieClearerLogoutHandler} in cookie authentication mode. When the request carries an
 * access token cookie, {@code POST /logout} is sent to Supabase with that token on the
 * {@link TaskExecutors#BLOCKING} executor, so the refresh token of the session stops working. The cookies are
 * cleared whether or not the revocation succeeds.</p>
 *
 * @since 0.0.1
 */
@Experimental
@Requires(beans = SupabaseAuthClient.class)
@Requires(condition = CookieBasedAuthenticationModeCondition.class)
@Replaces(TokenCookieClearerLogoutHandler.class)
@Singleton
public class SupabaseTokenCookieClearerLogoutHandler extends TokenCookieClearerLogoutHandler {
    /**
     * Supabase logout scope that revokes only the session of the presented access token.
     */
    public static final String SCOPE_LOCAL = "local";

    private static final Logger LOG = LoggerFactory.getLogger(SupabaseTokenCookieClearerLogoutHandler.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final SupabaseAuthClient client;
    private final ExecutorService executorService;

    /**
     * Creates the handler.
     *
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param refreshTokenCookieConfiguration Refresh token cookie configuration
     * @param redirectConfiguration Redirect configuration
     * @param redirectService Redirect service
     * @param client Supabase Auth client
     * @param executorService Executor the call to Supabase runs on
     */
    public SupabaseTokenCookieClearerLogoutHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                                   RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                                   RedirectConfiguration redirectConfiguration,
                                                   RedirectService redirectService,
                                                   SupabaseAuthClient client,
                                                   @Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        super(accessTokenCookieConfiguration, refreshTokenCookieConfiguration, redirectConfiguration, redirectService);
        this.client = client;
        this.executorService = executorService;
    }

    @Override
    public MutableHttpResponse<?> logout(HttpRequest<?> request) {
        accessToken(request).filter(value -> !value.isBlank()).ifPresent(this::revoke);
        return super.logout(request);
    }

    /**
     * The scope sent to {@code POST /logout}.
     *
     * @return {@value #SCOPE_LOCAL}: only the session of the presented access token is revoked
     */
    @NonNull
    protected String getScope() {
        return SCOPE_LOCAL;
    }

    private void revoke(@NonNull String accessToken) {
        executorService.execute(() -> {
            try {
                client.logout(BEARER_PREFIX + accessToken, getScope());
            } catch (RuntimeException e) {
                LOG.warn("Supabase logout failed: {}", e.getMessage());
                LOG.debug("Supabase logout failure", e);
            }
        });
    }

    /**
     * Returns the access token cookie of the request, if any.
     *
     * @param request The current request
     * @return The access token cookie value
     */
    @NonNull
    protected Optional<String> accessToken(@NonNull HttpRequest<?> request) {
        return request.getCookies().findCookie(accessTokenCookieConfiguration.getCookieName()).map(Cookie::getValue);
    }
}
