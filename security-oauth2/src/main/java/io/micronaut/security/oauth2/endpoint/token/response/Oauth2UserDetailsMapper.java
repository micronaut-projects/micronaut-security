package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;
import org.reactivestreams.Publisher;

public interface Oauth2UserDetailsMapper {

    Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse);
}
