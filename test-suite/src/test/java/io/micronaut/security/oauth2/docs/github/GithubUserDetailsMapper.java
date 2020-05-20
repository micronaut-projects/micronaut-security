package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.List;

@Named("github") // <1>
@Singleton
class GithubUserDetailsMapper implements OauthUserDetailsMapper {

    private final GithubApiClient apiClient;

    GithubUserDetailsMapper(GithubApiClient apiClient) {
        this.apiClient = apiClient;
    } // <2>

    @Override
    public Publisher<UserDetails> createUserDetails(TokenResponse tokenResponse) {
        return Publishers.just(new UnsupportedOperationException());
    }

    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) { // <3>
        return apiClient.getUser("token " + tokenResponse.getAccessToken())
                .map(user -> {
                    List<String> roles = Collections.singletonList("ROLE_GITHUB");
                    return new UserDetails(user.getLogin(), roles); // <4>
                });
    }
}
//end::clazz[]