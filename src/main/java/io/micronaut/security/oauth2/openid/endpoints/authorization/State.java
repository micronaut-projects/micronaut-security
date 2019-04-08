package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nullable;
import java.net.URI;

public interface State {

    @Nullable
    URI getOriginalUri();
}
