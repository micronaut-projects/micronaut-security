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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.oauth2.client.OauthClient;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import jakarta.inject.Inject;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;

/**
 * Default implementation of {@link OauthController}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = {RedirectingLoginHandler.class, HttpHostResolver.class, HttpLocaleResolver.class})
@EachBean(OauthClient.class)
public class DefaultOauthController implements OauthController {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOauthController.class);

    private final OauthClient oauthClient;
    private final RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;

    private final ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;

    private final ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;
    private final HttpHostResolver httpHostResolver;
    private final HttpLocaleResolver httpLocaleResolver;

    /**
     * @param oauthClient                   The oauth client
     * @param loginHandler                  The login handler
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @since 4.7.0
     */
    @Inject
    DefaultOauthController(
        @Parameter OauthClient oauthClient,
        RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
        ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
        ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher,
        HttpHostResolver httpHostResolver,
        HttpLocaleResolver httpLocaleResolver
    ) {
        this.oauthClient = oauthClient;
        this.loginHandler = loginHandler;
        this.loginSuccessfulEventPublisher = loginSuccessfulEventPublisher;
        this.loginFailedEventPublisher = loginFailedEventPublisher;
        this.httpHostResolver = httpHostResolver;
        this.httpLocaleResolver = httpLocaleResolver;
    }

    /**
     * @param oauthClient                   The oauth client
     * @param loginHandler                  The login handler
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @deprecated Use {@link #DefaultOauthController(OauthClient, RedirectingLoginHandler, ApplicationEventPublisher, ApplicationEventPublisher, HttpHostResolver, HttpLocaleResolver)} instead
     */
    @Deprecated(forRemoval = true, since = "4.7.0")
    DefaultOauthController(@Parameter OauthClient oauthClient,
                           RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
                           ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
                           ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher) {
        this(
            oauthClient,
            loginHandler,
            loginSuccessfulEventPublisher,
            loginFailedEventPublisher,
            request -> null,
            new HttpLocaleResolver() {
                @Override
                public @NonNull Optional<Locale> resolve(@NonNull HttpRequest<?> context) {
                    return Optional.of(resolveOrDefault(context));
                }

                @Override
                public @NonNull Locale resolveOrDefault(@NonNull HttpRequest<?> context) {
                    return Locale.getDefault();
                }
            }
        );
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
        Publisher<AuthenticationResponse> authenticationResponse = oauthClient.onCallback(request);
        return Flux.from(authenticationResponse).map(response -> {

            if (response.isAuthenticated() && response.getAuthentication().isPresent()) {
                Authentication authentication = response.getAuthentication().get();
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
            } else {
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
        }).defaultIfEmpty(HttpResponse.status(HttpStatus.UNAUTHORIZED));

    }

}
