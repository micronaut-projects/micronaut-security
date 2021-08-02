package io.micronaut.security.oauth2.docs.github

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.security.authentication.AuthenticationResponse;

//tag::clazz[]
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.token.config.TokenConfiguration
import org.reactivestreams.Publisher

import jakarta.inject.Named
import jakarta.inject.Singleton
import reactor.core.publisher.Flux

@Named("github") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
@Singleton
class GithubUserDetailsMapper implements OauthUserDetailsMapper {

    private final GithubApiClient apiClient
    private final TokenConfiguration tokenConfiguration

    GithubUserDetailsMapper(GithubApiClient apiClient,
                            TokenConfiguration tokenConfiguration) { // <2>
        this.apiClient = apiClient
        this.tokenConfiguration = tokenConfiguration
    }

    @Override
    Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        Flux.from(apiClient.getUser("token ${tokenResponse.accessToken}"))
            .map({ user ->
                AuthenticationResponse.build(user.login, ["ROLE_GITHUB"], tokenConfiguration) // <4>
            })
    }
}
//end::clazz[]