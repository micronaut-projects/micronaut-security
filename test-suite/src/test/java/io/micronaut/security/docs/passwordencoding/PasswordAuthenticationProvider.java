package io.micronaut.security.docs.passwordencoding;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Singleton;

import java.util.UUID;

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class PasswordAuthenticationProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {

    private final UserStore userStore;
    private final PasswordEncoder passwordEncoder;
    private final String unknownUserPassword;

    PasswordAuthenticationProvider(UserStore userStore, PasswordEncoder passwordEncoder) {
        this.userStore = userStore;
        this.passwordEncoder = passwordEncoder;
        this.unknownUserPassword = passwordEncoder.encode(UUID.randomUUID().toString()); // <1>
    }

    @Override
    public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
        String encodedPassword = userStore.findEncodedPassword(authRequest.getIdentity());
        boolean matches = passwordEncoder.matches(authRequest.getSecret(),
                encodedPassword != null ? encodedPassword : unknownUserPassword); // <2>
        return encodedPassword != null && matches
                ? AuthenticationResponse.success(authRequest.getIdentity())
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH); // <3>
    }
}
//end::clazz[]
