package io.micronaut.security.oauth2.docs.github

//tag::clazz[]
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import org.reactivestreams.Publisher
import jakarta.inject.Named
import jakarta.inject.Singleton
import reactor.core.publisher.Flux

@Named("github") // <1>
@Singleton
internal class GithubAuthenticationMapper(private val apiClient: GithubApiClient) // <2>
    : OauthAuthenticationMapper {

    override fun createAuthenticationResponse(tokenResponse: TokenResponse, state: State?): Publisher<AuthenticationResponse> { // <3>
        return Flux.from(apiClient.getUser("token " + tokenResponse.accessToken))
                .map { user ->
                    AuthenticationResponse.success(user.login, listOf("ROLE_GITHUB")) // <4>
                }
    }
}
//end::clazz[]
