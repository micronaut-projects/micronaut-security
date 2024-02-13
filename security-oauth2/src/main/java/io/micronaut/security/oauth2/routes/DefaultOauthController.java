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
package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.oauth2.client.OauthClient;
import java.util.Map;
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
@Requires(beans = RedirectingLoginHandler.class, classes = HttpRequest.class)
@EachBean(OauthClient.class)
public class DefaultOauthController implements OauthController {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOauthController.class);

    private final OauthClient oauthClient;
    private final RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;

    private final ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;

    private final ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;

    /**
     * @param oauthClient                   The oauth client
     * @param loginHandler                  The login handler
     * @param loginSuccessfulEventPublisher Application event publisher for {@link LoginSuccessfulEvent}.
     * @param loginFailedEventPublisher     Application event publisher for {@link LoginFailedEvent}.
     */
    DefaultOauthController(@Parameter OauthClient oauthClient,
                           RedirectingLoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler,
                           ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher,
                           ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher) {
        this.oauthClient = oauthClient;
        this.loginHandler = loginHandler;
        this.loginSuccessfulEventPublisher = loginSuccessfulEventPublisher;
        this.loginFailedEventPublisher = loginFailedEventPublisher;
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
                loginSuccessfulEventPublisher.publishEvent(new LoginSuccessfulEvent(authentication));
                return loginHandler.loginSuccess(authentication, request);
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Authentication failed: {}", response.getMessage().orElse("unknown reason"));
                }
                loginFailedEventPublisher.publishEvent(new LoginFailedEvent(response));
                return loginHandler.loginFailed(response, request);
            }
        }).defaultIfEmpty(HttpResponse.status(HttpStatus.UNAUTHORIZED));

    }

}
