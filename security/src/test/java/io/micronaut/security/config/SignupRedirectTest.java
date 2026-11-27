package io.micronaut.security.config;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignupRedirectTest {

    @Test
    void signupRedirectsDefaultToTheRoot() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SignupRedirectConfiguration configuration = context.getBean(SignupRedirectConfiguration.class);
            assertEquals("/", configuration.getSuccess());
            assertEquals("/", configuration.getFailure());
        }
    }

    @Test
    void signupRedirectsAreReadNextToTheOtherRedirects() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "micronaut.security.redirect.login-success", "/welcome",
                "micronaut.security.redirect.signup.success", "/signin",
                "micronaut.security.redirect.signup.failure", "/signup/failed"))) {
            SignupRedirectConfiguration configuration = context.getBean(SignupRedirectConfiguration.class);
            assertEquals("/signin", configuration.getSuccess());
            assertEquals("/signup/failed", configuration.getFailure());
            // RedirectConfigurationProperties binds the same prefix and is unaffected
            assertEquals("/welcome", context.getBean(RedirectConfiguration.class).getLoginSuccess());
        }
    }

    @Test
    void settersChangeTheSignupRedirects() {
        SignupRedirectConfigurationProperties properties = new SignupRedirectConfigurationProperties();
        properties.setSuccess("/signin");
        properties.setFailure("/signup/failed");
        assertEquals("/signin", properties.getSuccess());
        assertEquals("/signup/failed", properties.getFailure());
    }
}
