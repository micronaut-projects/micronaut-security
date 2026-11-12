package io.micronaut.docs.security.securityRule.custom

import io.micronaut.context.annotation.Requires
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'doccustom')
class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
    AuthenticationProviderUserPassword() {
        super([new SuccessAuthenticationScenario('user')])
    }
}
