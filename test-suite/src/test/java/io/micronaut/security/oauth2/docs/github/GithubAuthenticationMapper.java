package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.token.config.TokenConfiguration;
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
    private final TokenConfiguration tokenConfiguration;

    GithubAuthenticationMapper(GithubApiClient apiClient,
                            TokenConfiguration tokenConfiguration) {
        this.apiClient = apiClient;
        this.tokenConfiguration = tokenConfiguration;
    } // <2>

    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        return Flux.from(apiClient.getUser("token " + tokenResponse.getAccessToken()))
                .map(user -> {
                    List<String> roles = Collections.singletonList("ROLE_GITHUB");
                    return AuthenticationResponse.build(user.getLogin(), roles, tokenConfiguration); // <4>
                });
    }
}
//end::clazz[]