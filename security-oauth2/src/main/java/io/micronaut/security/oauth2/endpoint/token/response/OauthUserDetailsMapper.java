package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;
import org.reactivestreams.Publisher;

public interface OauthUserDetailsMapper {

    String PROVIDER_KEY = "oauth2Provider";

    Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse);
}
