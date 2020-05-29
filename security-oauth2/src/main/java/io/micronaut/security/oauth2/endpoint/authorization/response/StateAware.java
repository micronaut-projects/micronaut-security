package io.micronaut.security.oauth2.endpoint.authorization.response;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;

public interface StateAware {

    /**
     * @return The OAuth state
     */
    @Nullable
    State getState();
}
