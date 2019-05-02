package io.micronaut.security.oauth2.client;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;

import java.util.Map;

public interface OauthClient {

    String getName();

    HttpResponse authorizationRedirect(HttpRequest originating);

    Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request);

}
