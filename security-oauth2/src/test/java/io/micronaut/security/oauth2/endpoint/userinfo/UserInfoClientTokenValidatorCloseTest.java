package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.client.HttpClient;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserInfoClientTokenValidatorCloseTest {

    private static final String SPEC_NAME = "UserInfoClientTokenValidatorCloseTest";

    @Test
    void destroyingTheValidatorClosesItsHttpClient() throws Exception {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("spec.name", SPEC_NAME))) {
            UserInfoClientTokenValidator validator = ctx.getBean(UserInfoClientTokenValidator.class);
            HttpClient httpClient = httpClient(validator);
            assertTrue(httpClient.isRunning());

            ctx.destroyBean(UserInfoClientTokenValidator.class);

            assertFalse(httpClient.isRunning());
        }
    }

    private static HttpClient httpClient(UserInfoClientTokenValidator validator) throws ReflectiveOperationException {
        Field field = UserInfoClientTokenValidator.class.getDeclaredField("httpClient");
        field.setAccessible(true);
        return (HttpClient) field.get(validator);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Factory
    static class UserInfoConfigurationFactory {
        @Singleton
        UserInfoClientTokenValidatorConfiguration userInfoConfiguration() {
            return new UserInfoClientTokenValidatorConfiguration("http://localhost:8080", "authserver");
        }
    }
}
