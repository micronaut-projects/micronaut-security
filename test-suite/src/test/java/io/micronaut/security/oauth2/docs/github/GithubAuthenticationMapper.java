package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.token.config.TokenConfiguration;
import org.reactivestreams.Publisher;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.List;

@Named("github") // <1>
@Singleton
public class GithubAuthenticationMapper implements OauthAuthenticationMapper {

    private final GithubApiClient apiClient;
    private final TokenConfiguration tokenConfiguration;

    public GithubAuthenticationMapper(GithubApiClient apiClient,
                                      TokenConfiguration tokenConfiguration) {  // <2>
        this.apiClient = apiClient;
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        return apiClient.getUser("token " + tokenResponse.getAccessToken())
                .map(user -> {
                    List<String> roles = Collections.singletonList("ROLE_GITHUB");
                    return AuthenticationResponse.build(user.getLogin(), roles, tokenConfiguration); // <4>
                });
    }
}
//end::clazz[]