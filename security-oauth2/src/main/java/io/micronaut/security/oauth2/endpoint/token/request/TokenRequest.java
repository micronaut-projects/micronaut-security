package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;

public interface TokenRequest {

    Publisher<TokenResponse> send();
}
