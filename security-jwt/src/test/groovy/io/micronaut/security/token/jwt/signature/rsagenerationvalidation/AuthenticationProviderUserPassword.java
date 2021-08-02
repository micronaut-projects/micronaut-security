package io.micronaut.security.token.jwt.signature.rsagenerationvalidation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import jakarta.inject.Singleton;

import java.util.Collections;

@Singleton
@Requires(property = "spec.name", value = "rsajwtgateway")
public class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
    public AuthenticationProviderUserPassword() {
        super(Collections.singletonList(new SuccessAuthenticationScenario("user")));
    }
}
