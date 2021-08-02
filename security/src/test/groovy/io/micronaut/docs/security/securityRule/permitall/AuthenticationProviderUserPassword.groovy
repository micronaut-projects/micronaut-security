package io.micronaut.docs.security.securityRule.permitall

import io.micronaut.context.annotation.Requires
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Singleton
@Requires(property = 'spec.name', value = 'docpermitall')
class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
    AuthenticationProviderUserPassword() {
        super([new SuccessAuthenticationScenario('user'), new SuccessAuthenticationScenario('admin', ['ROLE_ADMIN'])])
    }
}
