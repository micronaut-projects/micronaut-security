package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider
import io.micronaut.security.password.PasswordEncoder
import jakarta.inject.Singleton
import java.util.UUID

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class PasswordAuthenticationProvider(
    private val userStore: UserStore,
    private val passwordEncoder: PasswordEncoder
) : HttpRequestExecutorAuthenticationProvider<Any> {

    private val unknownUserPassword = passwordEncoder.encode(UUID.randomUUID().toString()) // <1>

    override fun authenticate(
        requestContext: HttpRequest<Any>?,
        authRequest: AuthenticationRequest<String, String>
    ): AuthenticationResponse {
        val encodedPassword = userStore.findEncodedPassword(authRequest.identity)
        val matches = passwordEncoder.matches(authRequest.secret, encodedPassword ?: unknownUserPassword) // <2>
        return if (encodedPassword != null && matches)
            AuthenticationResponse.success(authRequest.identity)
        else AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH) // <3>
    }
}
//end::clazz[]
