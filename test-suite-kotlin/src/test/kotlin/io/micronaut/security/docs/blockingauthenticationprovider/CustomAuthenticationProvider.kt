package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.BlockingAuthenticationProvider
import jakarta.inject.Named

@Requires(property = "spec.name", value = "BlockingAuthenticationProviderTest")
//tag::clazz[]
@Named(CustomAuthenticationProvider.NAME)
class CustomAuthenticationProvider : BlockingAuthenticationProvider<HttpRequest<*>> {
    override fun authenticate(
        httpRequest: HttpRequest<*>,
        authenticationRequest: AuthenticationRequest<*, *>
    ): AuthenticationResponse {
        return if (authenticationRequest.identity == "user" && authenticationRequest.secret == "password")
            AuthenticationResponse.success("user")
        else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }

    override fun getName(): String = NAME

    companion object {
        const val NAME = "foo"
    }
}
//end::clazz[]
