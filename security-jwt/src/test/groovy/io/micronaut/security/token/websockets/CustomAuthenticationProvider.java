package io.micronaut.security.token.websockets;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import jakarta.inject.Singleton;

import java.util.Collections;

@Requires(property = "spec.name", value = "websockets-on-open-header")
@Singleton
public class CustomAuthenticationProvider extends MockAuthenticationProvider {
    public CustomAuthenticationProvider() {
        super(Collections.singletonList(new SuccessAuthenticationScenario("john")));
    }
}
