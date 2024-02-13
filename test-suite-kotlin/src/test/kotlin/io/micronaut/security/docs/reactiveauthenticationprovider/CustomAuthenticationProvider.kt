package io.micronaut.security.docs.reactiveauthenticationprovider

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestReactiveAuthenticationProvider
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

@Requires(property = "spec.name", value = "ReactiveAuthenticationProviderTest")
//tag::clazz[]
@Singleton
class CustomAuthenticationProvider<Any> :
    HttpRequestReactiveAuthenticationProvider<Any> {
    override fun authenticate(
        requestContext: HttpRequest<Any>?,
        authenticationRequest: AuthenticationRequest<String, String>
    ): Publisher<AuthenticationResponse> {
        val rsp = if (authenticationRequest.identity == "user" && authenticationRequest.secret == "password")
            AuthenticationResponse.success("user")
        else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        return Mono.create { emitter -> emitter.success(rsp) }
    }
}
//end::clazz[]
