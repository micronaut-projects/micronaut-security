package io.micronaut.security.oauth2

import io.micronaut.context.annotation.Primary
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServerResolver

import javax.annotation.Nonnull
import javax.annotation.Nullable
import javax.inject.Singleton
import javax.validation.constraints.NotNull

@Primary
@Singleton
class MockAuthorizationServerResolver implements AuthorizationServerResolver {
    private String authorizationserver

    MockAuthorizationServerResolver(@Value('${mockserver.authorizationserver:okta}') String authorizationserver) {
        this.authorizationserver = authorizationserver
    }

    @Nullable
    @Override
    String resolve(@Nonnull @NotNull String issuer) {
        return authorizationserver
    }
}
