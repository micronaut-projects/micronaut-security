package io.micronaut.security.oauth2.docs.github

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.core.annotation.Nullable
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import org.reactivestreams.Publisher

import jakarta.inject.Named
import jakarta.inject.Singleton
import reactor.core.publisher.Flux

@Named("github") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
@Singleton
class GithubAuthenticationMapper implements OauthAuthenticationMapper {

    private final GithubApiClient apiClient

    GithubAuthenticationMapper(GithubApiClient apiClient) { // <2>
        this.apiClient = apiClient
    }

    @Override
    Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        Flux.from(apiClient.getUser("token ${tokenResponse.accessToken}"))
            .map({ user ->
                AuthenticationResponse.success(user.login, ["ROLE_GITHUB"]) // <4>
            })
    }
}
//end::clazz[]
