package io.micronaut.docs.security.token.basicauth

import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.AuthenticationProvider
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "docsbasicauth")
@Singleton
class AuthenticationProviderUserPassword<T, I, S> implements AuthenticationProvider<T, I, S> {
    @Override
    AuthenticationResponse authenticate(T requestContext,
                                               AuthenticationRequest<I, S> authenticationRequest) {
        (authenticationRequest.getIdentity().equals("user") && authenticationRequest.getSecret().equals("password"))
                ? AuthenticationResponse.success("user")
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }
}
