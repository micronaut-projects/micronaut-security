package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider
import io.micronaut.security.password.PasswordEncoder
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class PasswordAuthenticationProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {

    private final UserStore userStore
    private final PasswordEncoder passwordEncoder
    private final String unknownUserPassword

    PasswordAuthenticationProvider(UserStore userStore, PasswordEncoder passwordEncoder) {
        this.userStore = userStore
        this.passwordEncoder = passwordEncoder
        this.unknownUserPassword = passwordEncoder.encode(UUID.randomUUID().toString()) // <1>
    }

    @Override
    AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
        String encodedPassword = userStore.findEncodedPassword(authRequest.identity)
        boolean matches = passwordEncoder.matches(authRequest.secret, encodedPassword ?: unknownUserPassword) // <2>
        encodedPassword != null && matches
                ? AuthenticationResponse.success(authRequest.identity)
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH) // <3>
    }
}
//end::clazz[]
