/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.handlers.RedirectingLoginhandler;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import java.util.Map;

/**
 * Default implementation of {@link OauthController}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@EachBean(OauthClient.class)
public class DefaultOauthController implements OauthController {

    private final OauthClient oauthClient;
    private final LoginHandler loginHandler;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * @param oauthClient The oauth client
     * @param loginHandler The login handler
     * @param eventPublisher The event publisher
     */
    DefaultOauthController(@Parameter OauthClient oauthClient,
                           RedirectingLoginhandler loginHandler,
                           ApplicationEventPublisher eventPublisher) {
        this.oauthClient = oauthClient;
        this.loginHandler = loginHandler;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public OauthClient getClient() {
        return oauthClient;
    }

    @Override
    public HttpResponse logout(HttpRequest request, Authentication authentication) {
        if (oauthClient instanceof OpenIdClient) {
            return ((OpenIdClient) oauthClient).endSessionRedirect(request, authentication).orElse(null);
        } else {
            return null;
        }
    }

    @Override
    public Publisher<HttpResponse> login(HttpRequest request) {
        return oauthClient.authorizationRedirect(request);
    }

    @Override
    public Publisher<HttpResponse> callback(HttpRequest<Map<String, Object>> request) {
        Publisher<AuthenticationResponse> authenticationResponse = oauthClient.onCallback(request);
        return Flowable.fromPublisher(authenticationResponse).map(response -> {
            if (response.isAuthenticated()) {
                UserDetails userDetails = (UserDetails) response;
                eventPublisher.publishEvent(new LoginSuccessfulEvent(userDetails));
                return loginHandler.loginSuccess(userDetails, request);
            } else {
                AuthenticationFailed authenticationFailed = (AuthenticationFailed) response;
                eventPublisher.publishEvent(new LoginFailedEvent(authenticationFailed));
                return loginHandler.loginFailed(authenticationFailed);
            }
        }).defaultIfEmpty(HttpResponse.status(HttpStatus.UNAUTHORIZED));

    }

}
