package io.micronaut.security.token.multitenancy.principal

import io.micronaut.context.annotation.Requires
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'multitenancy.principal.gateway')
class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
    AuthenticationProviderUserPassword() {
        super([new SuccessAuthenticationScenario('sherlock'), new SuccessAuthenticationScenario('watson')])
    }
}

