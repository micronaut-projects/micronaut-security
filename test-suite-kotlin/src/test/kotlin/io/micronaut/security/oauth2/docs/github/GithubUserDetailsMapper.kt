package io.micronaut.security.oauth2.docs.github

//tag::clazz[]
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import org.reactivestreams.Publisher
import java.lang.UnsupportedOperationException

import javax.inject.Named
import javax.inject.Singleton

@Named("github") // <1>
@Singleton
internal class GithubUserDetailsMapper(private val apiClient: GithubApiClient) // <2>
    : OauthUserDetailsMapper {

    override fun createAuthenticationResponse(tokenResponse: TokenResponse, state: State?): Publisher<AuthenticationResponse> { // <3>
        return apiClient.getUser("token " + tokenResponse.accessToken)
                .map { user ->
                    UserDetails(user.login, listOf("ROLE_GITHUB")) // <4>
                }
    }
}
//end::clazz[]