package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.AuthenticationProvider
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "AuthenticationProviderTest")
//tag::clazz[]
@Singleton
class CustomAuthenticationProvider :
    HttpRequestAuthenticationProvider<Any> {
    override fun authenticate(
        requestContext: HttpRequest<Any>?,
        authRequest: AuthenticationRequest<String, String>
    ): AuthenticationResponse {
        return if (authRequest.identity == "user" && authRequest.secret == "password")
            AuthenticationResponse.success("user")
        else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }

}
//end::clazz[]
