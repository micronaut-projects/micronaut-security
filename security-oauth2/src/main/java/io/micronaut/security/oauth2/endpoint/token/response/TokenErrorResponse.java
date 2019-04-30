package io.micronaut.security.oauth2.endpoint.token.response;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface TokenErrorResponse {

    @Nonnull
    TokenError getError();

    @Nullable
    String getErrorDescription();

    @Nullable
    String getErrorUri();
}
