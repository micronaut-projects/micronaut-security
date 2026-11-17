package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtCookieSameSiteInvalidTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "micronaut.security.token.cookie.cookie-same-site",
        "micronaut.security.token.refresh.cookie.cookie-same-site"
    })
    void applicationFailsToStartWithConfigurationExceptionIfSameSiteIsInvalid(String property) {
        Map<String, Object> configuration = Map.of(
            "spec.name", "JwtCookieSameSiteInvalidTest",
            "micronaut.security.authentication", "cookie",
            property, "nonesense",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa");

        Throwable t = assertThrows(RuntimeException.class, () -> ApplicationContext.run(EmbeddedServer.class, configuration).close());
        while (!(t instanceof ConfigurationException) && t.getCause() != null) {
            t = t.getCause();
        }

        ConfigurationException e = assertInstanceOf(ConfigurationException.class, t);
        assertTrue(e.getMessage().contains(property));
        assertTrue(e.getMessage().contains("nonesense"));
    }
}
