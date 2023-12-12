package io.micronaut.security.docs.blockingauthenticationprovider

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.BlockingAuthenticationProvider
import jakarta.inject.Named

@Requires(property = "spec.name", value = "BlockingAuthenticationProviderTest")
//tag::clazz[]
@Named(CustomAuthenticationProvider.NAME)
class CustomAuthenticationProvider implements BlockingAuthenticationProvider<HttpRequest<?>> {
    static final String NAME = "foo"

    @Override
    AuthenticationResponse authenticate(HttpRequest<?> httpRequest,
                                               AuthenticationRequest<?, ?> authenticationRequest) {
        (authenticationRequest.identity == "user" && authenticationRequest.secret == "password") ?
                AuthenticationResponse.success("user") :
                AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
    }

    @Override
    @NonNull String getName() {
        NAME
    }
}
//end::clazz[]
