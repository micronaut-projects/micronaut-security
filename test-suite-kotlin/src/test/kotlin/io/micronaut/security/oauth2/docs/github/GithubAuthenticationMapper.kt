package io.micronaut.security.oauth2.docs.github

import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.token.config.TokenConfiguration
import org.reactivestreams.Publisher
import javax.inject.Named
import javax.inject.Singleton

//tag::clazz[]
@Named("github") // <1>
@Singleton
class GithubAuthenticationMapper // <2>
(private val apiClient: GithubApiClient,
 private val tokenConfiguration: TokenConfiguration) : OauthAuthenticationMapper {
    override fun createAuthenticationResponse(tokenResponse: TokenResponse, state: State?): Publisher<AuthenticationResponse> { // <3>
        return apiClient.getUser("token " + tokenResponse.accessToken)
                .map { user: GithubUser ->
                    val roles = listOf("ROLE_GITHUB")
                    AuthenticationResponse.build(user.login!!, roles, tokenConfiguration) // <4>
                }
    }
}