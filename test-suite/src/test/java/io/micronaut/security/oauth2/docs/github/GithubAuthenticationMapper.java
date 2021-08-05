package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;

import jakarta.inject.Named;
import jakarta.inject.Singleton;
import reactor.core.publisher.Flux;

import java.util.Collections;
import java.util.List;

@Named("github") // <1>
@Singleton
class GithubAuthenticationMapper implements OauthAuthenticationMapper {

    private final GithubApiClient apiClient;

    GithubAuthenticationMapper(GithubApiClient apiClient) { // <2>
        this.apiClient = apiClient;
    }

    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        return Flux.from(apiClient.getUser("token " + tokenResponse.getAccessToken()))
                .map(user -> {
                    List<String> roles = Collections.singletonList("ROLE_GITHUB");
                    return AuthenticationResponse.success(user.getLogin(), roles); // <4>
                });
    }
}
//end::clazz[]
