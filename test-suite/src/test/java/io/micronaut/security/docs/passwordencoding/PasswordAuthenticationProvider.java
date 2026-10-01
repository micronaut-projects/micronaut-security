package io.micronaut.security.docs.passwordencoding;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Singleton;

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class PasswordAuthenticationProvider<B> implements HttpRequestAuthenticationProvider<B> {

    private final UserStore userStore;
    private final PasswordEncoder passwordEncoder;

    PasswordAuthenticationProvider(UserStore userStore, PasswordEncoder passwordEncoder) {
        this.userStore = userStore;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
        return userStore.findEncodedPassword(authRequest.getIdentity())
                .filter(encodedPassword -> passwordEncoder.matches(authRequest.getSecret(), encodedPassword)) // <1>
                .map(encodedPassword -> AuthenticationResponse.success(authRequest.getIdentity()))
                .orElseGet(() -> AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH));
    }
}
//end::clazz[]
