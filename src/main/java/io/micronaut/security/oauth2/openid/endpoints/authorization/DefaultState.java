package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nullable;
import java.net.URI;

/**
 * Default implementation of {@link State}.
 * @author James Kleeh
 * @since 1.0.0
 */
public class DefaultState implements State {

    private URI originalUri;

    @Override
    @Nullable
    public URI getOriginalUri() {
        return originalUri;
    }

    /**
     *
     * @param originalUri Original Uri
     */
    public void setOriginalUri(URI originalUri) {
        this.originalUri = originalUri;
    }
}
