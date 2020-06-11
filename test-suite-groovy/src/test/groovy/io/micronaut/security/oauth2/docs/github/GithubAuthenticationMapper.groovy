package io.micronaut.security.oauth2.docs.github

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationResponse;

//tag::clazz[]
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.token.config.TokenConfiguration
import org.reactivestreams.Publisher

import javax.inject.Named
import javax.inject.Singleton

@Named("github") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
@Singleton
class GithubAuthenticationMapper implements OauthAuthenticationMapper {

    private final TokenConfiguration tokenConfiguration
    private final GithubApiClient apiClient

    GithubAuthenticationMapper(TokenConfiguration tokenConfiguration, GithubApiClient apiClient) { // <2>
        this.tokenConfiguration = tokenConfiguration
        this.apiClient = apiClient
    }

    @Override
    Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        apiClient.getUser("token ${tokenResponse.accessToken}")
            .map({ user ->
                AuthenticationResponse.build(user.login, ['ROLE_GITHUB'], tokenConfiguration) // <4>
            })
    }
}
//end::clazz[]