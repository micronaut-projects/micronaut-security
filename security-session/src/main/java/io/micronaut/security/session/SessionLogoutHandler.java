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
package io.micronaut.security.session;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.HttpSessionFilter;
import io.micronaut.session.http.HttpSessionIdEncoder;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * {@link LogoutHandler} implementation for Session-Based Authentication.
 * On logout, the session is deleted from the {@link SessionStore} and the session identifier is expired in the
 * response (e.g. the session cookie is cleared), so the session identifier cannot be reused after logout.
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(condition = SessionAuthenticationModeCondition.class)
@Singleton
public class SessionLogoutHandler implements LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(SessionLogoutHandler.class);

    @Nullable
    protected final String logout;

    @Nullable
    private final SessionStore<Session> sessionStore;

    private final List<HttpSessionIdEncoder> sessionIdEncoders;

    /**
     * Constructor.
     * @param redirectConfiguration Redirect Configuration
     * @param redirectService Redirection Service
     * @param sessionStore The session store
     * @param sessionIdEncoders Session ID encoders used to expire the session identifier in the response
     */
    @Inject
    public SessionLogoutHandler(RedirectConfiguration redirectConfiguration,
                                RedirectService redirectService,
                                SessionStore<Session> sessionStore,
                                List<HttpSessionIdEncoder> sessionIdEncoders) {
        this.logout = redirectConfiguration.isEnabled() ? redirectService.logoutUrl() : null;
        this.sessionStore = sessionStore;
        this.sessionIdEncoders = sessionIdEncoders;
    }

    /**
     * Constructor.
     * @param redirectConfiguration Redirect Configuration
     * @param redirectService Redirection Service
     * @deprecated Use {@link #SessionLogoutHandler(RedirectConfiguration, RedirectService, SessionStore, List)} instead. Without a {@link SessionStore}, the session is not deleted on logout; only the authentication is removed from it.
     */
    @Deprecated(forRemoval = true, since = "5.4.0")
    public SessionLogoutHandler(RedirectConfiguration redirectConfiguration, RedirectService redirectService) {
        this.logout = redirectConfiguration.isEnabled() ? redirectService.logoutUrl() : null;
        this.sessionStore = null;
        this.sessionIdEncoders = Collections.emptyList();
    }

    @Override
    public MutableHttpResponse<?> logout(HttpRequest<?> request) {
        Optional<Session> session = SessionForRequest.find(request);
        session.ifPresent(s -> invalidateSession(request, s));
        MutableHttpResponse<?> response = logoutResponse();
        session.ifPresent(s -> expireSessionId(request, response, s));
        return response;
    }

    @NonNull
    private MutableHttpResponse<?> logoutResponse() {
        try {
            return logout == null ? HttpResponse.ok() : HttpResponse.seeOther(new URI(logout));
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    /**
     * Removes the authentication from the session, detaches the session from the request so that it is not saved
     * again by {@link HttpSessionFilter}, marks it as expired and deletes it from the {@link SessionStore}.
     * @param request HTTP Request
     * @param session The session associated to the request
     */
    private void invalidateSession(@NonNull HttpRequest<?> request, @NonNull Session session) {
        session.remove(SecurityFilter.AUTHENTICATION);
        if (sessionStore == null) {
            return;
        }
        request.getAttributes().remove(HttpSessionFilter.SESSION_ATTRIBUTE);
        session.setMaxInactiveInterval(Duration.ZERO);
        sessionStore.deleteSession(session.getId()).exceptionally(throwable -> {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Could not delete session {} on logout", session.getId(), throwable);
            }
            return false;
        });
    }

    /**
     * Encodes the expired session in the response so the client discards the session identifier (e.g. an expired
     * session cookie is sent).
     * @param request HTTP Request
     * @param response HTTP Response
     * @param session The expired session
     */
    private void expireSessionId(@NonNull HttpRequest<?> request,
                                 @NonNull MutableHttpResponse<?> response,
                                 @NonNull Session session) {
        if (!session.isExpired()) {
            return;
        }
        for (HttpSessionIdEncoder encoder : sessionIdEncoders) {
            encoder.encodeId(request, response, session);
        }
    }
}
