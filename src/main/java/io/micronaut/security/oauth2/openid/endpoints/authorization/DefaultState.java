package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nullable;
import java.net.URI;

public class DefaultState implements State {

    private URI originalUri;

    @Override
    @Nullable
    public URI getOriginalUri() {
        return originalUri;
    }

    public void setOriginalUri(URI originalUri) {
        this.originalUri = originalUri;
    }
}
