package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nullable;
import java.net.URI;

/**
 * Allows to restore the previous state of the application, other use of state parameter is to mitigate CSRF attacks.
 * @author James Kleeh
 * @since 1.0.0
 */
public interface State {

    /**
     *
     * @return Original URI which caused the authorization request to be triggered.
     */
    @Nullable
    URI getOriginalUri();
}
