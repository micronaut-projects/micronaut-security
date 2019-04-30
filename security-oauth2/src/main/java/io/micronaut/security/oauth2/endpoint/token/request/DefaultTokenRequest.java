package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import org.reactivestreams.Publisher;

public class DefaultTokenRequest implements TokenRequest {


    DefaultTokenRequest(RxHttpClient httpClient,
                        MutableHttpRequest<AuthorizationCodeGrant> request) {}

    @Override
    public Publisher<TokenResponse> send() {
        return null;
    }
}
