package io.micronaut.security.token.jwt.accesstokenexpiration

import io.micronaut.context.annotation.Requires
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'accesstokenexpiration')
class AuthenticationProviderUserPassword extends MockAuthenticationProvider {

    AuthenticationProviderUserPassword() {
        super([new SuccessAuthenticationScenario('user')])
    }
}
