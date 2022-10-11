package io.micronaut.docs.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "securitysession")
@Singleton
class AuthenticationProviderUserPassword extends MockAuthenticationProvider  {
    AuthenticationProviderUserPassword() {
        super([new SuccessAuthenticationScenario('sherlock')])
    }
}
