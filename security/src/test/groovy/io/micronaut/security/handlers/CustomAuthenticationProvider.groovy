package io.micronaut.security.handlers

import io.micronaut.context.annotation.Requires
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "RedirectRejectionHandlerSpec")
@Singleton
class CustomAuthenticationProvider extends MockAuthenticationProvider {
    CustomAuthenticationProvider() {
        super([new SuccessAuthenticationScenario('sherlock')])
    }
}
