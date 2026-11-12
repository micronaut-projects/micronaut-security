package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.BeanInstantiationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwksSignatureConfigurationPropertiesTest {

    @Test
    void validJwksUrlIsAccepted() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "micronaut.security.token.jwt.signatures.jwks.test.url", "https://example.com/.well-known/jwks.json"))) {
            JwksSignatureConfiguration configuration = context.getBean(JwksSignatureConfiguration.class);

            assertEquals("https://example.com/.well-known/jwks.json", configuration.getUrl());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "example.com/.well-known/jwks.json",
        "/.well-known/jwks.json"
    })
    void jwksUrlMustBeValid(String url) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class, () -> {
            try (ApplicationContext context = ApplicationContext.run(Map.of(
                    "micronaut.security.token.jwt.signatures.jwks.test.url", url))) {
                context.getBean(JwksSignatureConfiguration.class);
            }
        });

        assertTrue(exception.getMessage().contains("url - must be a valid URL"));
    }
}
