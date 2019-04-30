package io.micronaut.security.oauth2.routes;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.oauth2.client.Oauth2Client;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import java.util.Map;

@EachBean(Oauth2Client.class)
public class DefaultOauth2Controller implements Oauth2Controller {

    private final Oauth2Client oauth2Client;
    private final LoginHandler loginHandler;
    private final ApplicationEventPublisher eventPublisher;

    DefaultOauth2Controller(@Parameter Oauth2Client oauth2Client,
                            LoginHandler loginHandler,
                            ApplicationEventPublisher eventPublisher) {
        this.oauth2Client = oauth2Client;
        this.loginHandler = loginHandler;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public HttpResponse login(HttpRequest request) {
        return oauth2Client.authorizationRedirect(request);
    }

    @Override
    public Publisher<HttpResponse> callback(HttpRequest<Map<String, Object>> request) {
        Publisher<AuthenticationResponse> authenticationResponse = oauth2Client.onCallback(request);
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
