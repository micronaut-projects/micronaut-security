package io.micronaut.security.oauth2.docs.github

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton

@Named("github") // <1>
@Singleton
internal class GithubUserDetailsMapper(private val apiClient: GithubApiClient) // <2>
    : OauthUserDetailsMapper {

    override fun createUserDetails(tokenResponse: TokenResponse): Publisher<UserDetails> { // <3>
        return apiClient.getUser("token " + tokenResponse.accessToken)
                .map { user ->
                    UserDetails(user.login, listOf("ROLE_GITHUB")) // <4>
                }
    }
}
//end::clazz[]