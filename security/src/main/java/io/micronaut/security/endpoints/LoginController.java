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
package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.Authenticator;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Optional;

/**
 * Handles login requests.
 *
 * @param <B> The HTTP Request Body type
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(property = LoginControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(classes = Controller.class)
@Requires(beans = {LoginHandler.class, Authenticator.class, HttpHostResolver.class, HttpHostResolver.class})
@Controller("${" + LoginControllerConfigurationProperties.PREFIX + ".path:/login}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class LoginController<B> {

    private static final Logger LOG = LoggerFactory.getLogger(LoginController.class);

    protected final Authenticator<HttpRequest<B>> authenticator;
    protected final LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;
    protected final ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;
    protected final ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;
    protected final HttpHostResolver httpHostResolver;
    protected final HttpLocaleResolver httpLocaleResolver;
    protected final LoginControllerConfiguration loginControllerConfiguration;

    /**
     * @param authenticator                 {@link Authenticator} collaborator
     * @param loginHandler                  A collaborator which helps to build HTTP response depending on success or failure.
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @since 4.11.0
     */
    @Inject
    public LoginController(
            Authenticator<HttpRequest<B>> authenticator,
            LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
            ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
            ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher,
            HttpHostResolver httpHostResolver,
            HttpLocaleResolver httpLocaleResolver,
            LoginControllerConfiguration loginControllerConfiguration
    ) {
        this.authenticator = authenticator;
        this.loginHandler = loginHandler;
        this.loginSuccessfulEventPublisher = loginSuccessfulEventPublisher;
        this.loginFailedEventPublisher = loginFailedEventPublisher;
        this.httpHostResolver = httpHostResolver;
        this.httpLocaleResolver = httpLocaleResolver;
        this.loginControllerConfiguration = loginControllerConfiguration;
    }

    /**
     * @param authenticator                 {@link Authenticator} collaborator
     * @param loginHandler                  A collaborator which helps to build HTTP response depending on success or failure.
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @since 4.7.0
     * @deprecated Use {@link LoginController(Authenticator, LoginHandler, ApplicationEventPublisher, ApplicationEventPublisher, HttpHostResolver, HttpLocaleResolver, LoginControllerConfiguration)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public LoginController(
        Authenticator<HttpRequest<B>> authenticator,
        LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
        ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
        ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher,
        HttpHostResolver httpHostResolver,
        HttpLocaleResolver httpLocaleResolver
    ) {
        this(authenticator,
                loginHandler,
                loginSuccessfulEventPublisher,
                loginFailedEventPublisher,
                httpHostResolver,
                httpLocaleResolver, new LoginControllerConfigurationProperties());
    }

    /**
     * @param authenticator                 {@link Authenticator} collaborator
     * @param loginHandler                  A collaborator which helps to build HTTP response depending on success or failure.
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     * @deprecated Use {@link #LoginController(Authenticator, LoginHandler, ApplicationEventPublisher, ApplicationEventPublisher)} instead
     */
    @Deprecated(forRemoval = true, since = "4.7.0")
    public LoginController(
        Authenticator<HttpRequest<B>> authenticator,
        LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
        ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
        ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher
    ) {
        this(
            authenticator,
            loginHandler,
            loginSuccessfulEventPublisher,
            loginFailedEventPublisher,
            request -> null,
            new HttpLocaleResolver() {
                @Override
                public @NonNull Optional<Locale> resolve(@NonNull HttpRequest<?> context) {
                    return Optional.of(Locale.getDefault());
                }

                @Override
                public @NonNull Locale resolveOrDefault(@NonNull HttpRequest<?> context) {
                    return Locale.getDefault();
                }
            },
                new LoginControllerConfigurationProperties()
        );
    }

    /**
     * @param usernamePasswordCredentials An instance of {@link UsernamePasswordCredentials} in the body payload
     * @param request                     The {@link HttpRequest} being executed
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    @SingleResult
    public Publisher<MutableHttpResponse<?>> login(@Valid @Body UsernamePasswordCredentials usernamePasswordCredentials, HttpRequest<B> request) {
        Optional<MediaType> contentTypeOptional = request.getContentType();
        if (!(contentTypeOptional.isPresent() && loginControllerConfiguration.getPostContentTypes().contains(contentTypeOptional.get()))) {
            return Publishers.just(HttpResponse.notFound());
        }
        return Flux.from(authenticator.authenticate(request, usernamePasswordCredentials))
            .map(authenticationResponse -> {
                if (authenticationResponse.isAuthenticated() && authenticationResponse.getAuthentication().isPresent()) {
                    Authentication authentication = authenticationResponse.getAuthentication().get();
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
                        LOG.trace("login failed for username: {}", usernamePasswordCredentials.getUsername());
                    }
                    loginFailedEventPublisher.publishEvent(
                        new LoginFailedEvent(
                            authenticationResponse,
                            usernamePasswordCredentials,
                            httpHostResolver.resolve(request),
                            httpLocaleResolver.resolveOrDefault(request)
                        )
                    );
                    return loginHandler.loginFailed(authenticationResponse, request);
                }
            }).switchIfEmpty(Mono.defer(() -> Mono.just(HttpResponse.status(HttpStatus.UNAUTHORIZED))));
    }
}
