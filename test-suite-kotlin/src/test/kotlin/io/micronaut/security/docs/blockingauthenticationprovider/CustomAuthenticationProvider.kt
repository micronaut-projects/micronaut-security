package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.AuthenticationProvider
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "AuthenticationProviderTest")
//tag::clazz[]
@Singleton
class CustomAuthenticationProvider :
    AuthenticationProvider<HttpRequest<*>> {
    override fun authenticate(
        httpRequest: HttpRequest<*>,
        authenticationRequest: AuthenticationRequest<*, *>
    ): AuthenticationResponse {
        return if (authenticationRequest.identity == "user" && authenticationRequest.secret == "password")
            AuthenticationResponse.success("user")
        else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }
}
//end::clazz[]
