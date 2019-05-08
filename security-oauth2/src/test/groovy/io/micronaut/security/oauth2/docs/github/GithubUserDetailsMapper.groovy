package io.micronaut.security.oauth2.docs.github

import io.micronaut.context.annotation.Requires;

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton

@Named("github") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
@Singleton
class GithubUserDetailsMapper implements OauthUserDetailsMapper {

    private final GithubApiClient apiClient

    GithubUserDetailsMapper(GithubApiClient apiClient) { // <2>
        this.apiClient = apiClient
    }

    @Override
    Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) { // <3>
        apiClient.getUser("token ${tokenResponse.accessToken}")
            .map({ user ->
                new UserDetails(user.login, ["ROLE_GITHUB"]) // <4>
            })
    }
}
//end::clazz[]