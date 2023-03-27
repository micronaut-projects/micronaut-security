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
package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.async.annotation.SingleResult;
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
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.Authenticator;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.validation.Validated;
import jakarta.validation.Valid;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Handles login requests.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(property = LoginControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = LoginHandler.class)
@Requires(beans = Authenticator.class)
@Controller("${" + LoginControllerConfigurationProperties.PREFIX + ".path:/login}")
@Secured(SecurityRule.IS_ANONYMOUS)
@Validated
public class LoginController {

    protected final Authenticator authenticator;
    protected final LoginHandler loginHandler;
    protected final ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;
    protected final ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;

    /**
     * @param authenticator                 {@link Authenticator} collaborator
     * @param loginHandler                  A collaborator which helps to build HTTP response depending on success or failure.
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     */
    public LoginController(Authenticator authenticator,
                           LoginHandler loginHandler,
                           ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
                           ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher) {
        this.authenticator = authenticator;
        this.loginHandler = loginHandler;
        this.loginSuccessfulEventPublisher = loginSuccessfulEventPublisher;
        this.loginFailedEventPublisher = loginFailedEventPublisher;
    }

    /**
     * @param usernamePasswordCredentials An instance of {@link UsernamePasswordCredentials} in the body payload
     * @param request                     The {@link HttpRequest} being executed
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    @SingleResult
    public Publisher<MutableHttpResponse<?>> login(@Valid @Body UsernamePasswordCredentials usernamePasswordCredentials, HttpRequest<?> request) {
        return Flux.from(authenticator.authenticate(request, usernamePasswordCredentials))
                .map(authenticationResponse -> {
                    if (authenticationResponse.isAuthenticated() && authenticationResponse.getAuthentication().isPresent()) {
                        Authentication authentication = authenticationResponse.getAuthentication().get();
                        loginSuccessfulEventPublisher.publishEvent(new LoginSuccessfulEvent(authentication));
                        return loginHandler.loginSuccess(authentication, request);
                    } else {
                        loginFailedEventPublisher.publishEvent(new LoginFailedEvent(authenticationResponse));
                        return loginHandler.loginFailed(authenticationResponse, request);
                    }
                }).switchIfEmpty(Mono.defer(() -> Mono.just(HttpResponse.status(HttpStatus.UNAUTHORIZED))));
    }
}
