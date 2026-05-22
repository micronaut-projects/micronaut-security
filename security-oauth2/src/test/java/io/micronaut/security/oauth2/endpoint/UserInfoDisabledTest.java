package io.micronaut.security.oauth2.endpoint;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.endpoint.userinfo.UserInfoClientTokenValidatorConfiguration;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.oauth2.userinfo.validator", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "UserInfoDisabledTest")
@MicronautTest(startApplication = false)
public class UserInfoDisabledTest {

    @Inject
    BeanContext beanContext;

    @Test
    void itIsPossibleToDisableTokenValidationViaConfiguration() {
        assertTrue(beanContext.containsBean(UserInfoClientTokenValidatorConfiguration.class));
        assertTrue(beanContext.getBeansOfType(TokenValidator.class).stream().noneMatch(v -> v.getClass().getSimpleName().equals("UserInfoClientTokenValidator")));
    }

    @Requires(property = "spec.name", value = "UserInfoDisabledTest")
    @Factory
    static class UserInfoClientConfigurationFactory {

        @Singleton
        UserInfoClientTokenValidatorConfiguration createUserInfoClientConfiguration() {
            return UserInfoClientTokenValidatorConfiguration.builder()
                .baseUrl("https://server.example.com")
                .name("example")
                .build();
        }
    }
}
