package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;

public abstract class AbstractTokenRequestContext<G, R extends TokenResponse> implements TokenRequestContext<G, R> {

    protected final MediaType mediaType;
    protected final SecureEndpoint endpoint;
    protected final OauthClientConfiguration clientConfiguration;

    public AbstractTokenRequestContext(MediaType mediaType,
                                       SecureEndpoint endpoint,
                                       OauthClientConfiguration clientConfiguration) {

        this.mediaType = mediaType;
        this.endpoint = endpoint;
        this.clientConfiguration = clientConfiguration;
    }

    @Override
    public MediaType getMediaType() {
        return mediaType;
    }

    @Override
    public SecureEndpoint getEndpoint() {
        return endpoint;
    }

    @Override
    public OauthClientConfiguration getClientConfiguration() {
        return clientConfiguration;
    }
}
