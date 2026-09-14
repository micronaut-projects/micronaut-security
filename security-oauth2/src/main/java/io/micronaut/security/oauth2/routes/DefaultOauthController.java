/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence;
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence;

import java.util.Map;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Default implementation of {@link OauthController}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = {RedirectingLoginHandler.class, HttpHostResolver.class, HttpLocaleResolver.class})
@EachBean(OauthClient.class)
public class DefaultOauthController implements OauthController {

    private static final String MESSAGE_NO_AUTHENTICATION_RESPONSE = "The OAuth 2.0 client did not produce an authentication response";

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOauthController.class);

    private final OauthClient oauthClient;
    private final RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;

    private final ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;

    private final ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;
    private final HttpHostResolver httpHostResolver;
    private final HttpLocaleResolver httpLocaleResolver;

    @Nullable
    private final StatePersistence statePersistence;

    @Nullable
    private final PkcePersistence pkcePersistence;

    @Nullable
    private final NoncePersistence noncePersistence;

    /**
     * @param oauthClient                   The oauth client
     * @param loginHandler                  The login handler
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @param statePersistence              The state persistence, if any
     * @param pkcePersistence               The PKCE persistence, if any
     * @param noncePersistence              The nonce persistence, if any
     * @since 5.4.0
     */
    DefaultOauthController(
        @Parameter OauthClient oauthClient,
        RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
        ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
        ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher,
        HttpHostResolver httpHostResolver,
        HttpLocaleResolver httpLocaleResolver,
        @Nullable StatePersistence statePersistence,
        @Nullable PkcePersistence pkcePersistence,
        @Nullable NoncePersistence noncePersistence
    ) {
        this.oauthClient = oauthClient;
        this.loginHandler = loginHandler;
        this.loginSuccessfulEventPublisher = loginSuccessfulEventPublisher;
        this.loginFailedEventPublisher = loginFailedEventPublisher;
        this.httpHostResolver = httpHostResolver;
        this.httpLocaleResolver = httpLocaleResolver;
        this.statePersistence = statePersistence;
        this.pkcePersistence = pkcePersistence;
        this.noncePersistence = noncePersistence;
    }

    @Override
    public OauthClient getClient() {
        return oauthClient;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> login(HttpRequest<?> request) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Received login request for provider [{}]", oauthClient.getName());
        }
        return oauthClient.authorizationRedirect(request);
    }

    @Override
    public Publisher<MutableHttpResponse<?>> callback(HttpRequest<Map<String, Object>> request) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Received callback from oauth provider [{}]", oauthClient.getName());
        }
        return Flux.from(oauthClient.onCallback(request))
                .map(response -> response.isAuthenticated() && response.getAuthentication().isPresent()
                        ? success(response.getAuthentication().get(), request)
                        : failure(response, request))
                .switchIfEmpty(Mono.fromSupplier(() -> failure(new AuthenticationFailed(MESSAGE_NO_AUTHENTICATION_RESPONSE), request)))
                .map(response -> clearPersistedValues(request, response));
    }

    /**
     * The state, PKCE code verifier and nonce are single-use values which have been consumed by the callback.
     * Ask each persistence mechanism to clear them so they cannot be replayed.
     *
     * @param request  The callback request
     * @param response The callback response
     * @return The callback response
     */
    private MutableHttpResponse<?> clearPersistedValues(@NonNull HttpRequest<?> request,
                                                        @NonNull MutableHttpResponse<?> response) {
        if (statePersistence != null) {
            statePersistence.clearState(request, response);
        }
        if (pkcePersistence != null) {
            pkcePersistence.clearPkce(request, response);
        }
        if (noncePersistence != null) {
            noncePersistence.clearNonce(request, response);
        }
        return response;
    }

    private MutableHttpResponse<?> failure(@NonNull AuthenticationResponse response,
                                           @NonNull HttpRequest<Map<String, Object>> request) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Authentication failed: {}", response.getMessage().orElse("unknown reason"));
        }
        loginFailedEventPublisher.publishEvent(
                new LoginFailedEvent(
                        response,
                        null,
                        httpHostResolver.resolve(request),
                        httpLocaleResolver.resolveOrDefault(request)
                )
        );
        return loginHandler.loginFailed(response, request);
    }

    private MutableHttpResponse<?> success(@NonNull Authentication authentication,
                                           @NonNull HttpRequest<Map<String, Object>> request) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Authentication succeeded. User [{}] is now logged in", authentication.getName());
        }
        loginSuccessfulEventPublisher.publishEvent(
                new LoginSuccessfulEvent(
                        authentication,
                        httpHostResolver.resolve(request),
                        httpLocaleResolver.resolveOrDefault(request)
                )
        );
        return loginHandler.loginSuccess(authentication, request);
    }
}
