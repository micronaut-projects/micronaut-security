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
import io.micronaut.security.oauth2.client.OauthClient;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import java.util.Map;

@EachBean(OauthClient.class)
public class DefaultOauthController implements OauthController {

    private final OauthClient oauthClient;
    private final LoginHandler loginHandler;
    private final ApplicationEventPublisher eventPublisher;

    DefaultOauthController(@Parameter OauthClient oauthClient,
                           LoginHandler loginHandler,
                           ApplicationEventPublisher eventPublisher) {
        this.oauthClient = oauthClient;
        this.loginHandler = loginHandler;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public HttpResponse login(HttpRequest request) {
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
