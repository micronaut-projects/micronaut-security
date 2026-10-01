package io.micronaut.security.password.argon2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.security.password.PasswordEncoder;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2PasswordEncoderConfigurationPropertiesTest {

    @Test
    void constantsDefineThePrefixAndTheDefaults() {
        assertEquals("micronaut.security.password.argon2", Argon2PasswordEncoderConfigurationProperties.PREFIX);
        assertEquals(19_456, Argon2PasswordEncoderConfigurationProperties.DEFAULT_MEMORY);
        assertEquals(2, Argon2PasswordEncoderConfigurationProperties.DEFAULT_ITERATIONS);
        assertEquals(1, Argon2PasswordEncoderConfigurationProperties.DEFAULT_PARALLELISM);
        assertEquals(16, Argon2PasswordEncoderConfigurationProperties.DEFAULT_SALT_LENGTH);
        assertEquals(32, Argon2PasswordEncoderConfigurationProperties.DEFAULT_HASH_LENGTH);
        assertEquals(262_144, Argon2PasswordEncoderConfigurationProperties.DEFAULT_MAX_MEMORY);
        assertEquals(10, Argon2PasswordEncoderConfigurationProperties.DEFAULT_MAX_ITERATIONS);
    }

    @Test
    void defaultsApplyWithoutConfiguration() {
        try (ApplicationContext context = ApplicationContext.run()) {
            Argon2PasswordEncoderConfiguration configuration = context.getBean(Argon2PasswordEncoderConfiguration.class);

            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_MEMORY, configuration.getMemory());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_ITERATIONS, configuration.getIterations());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_PARALLELISM, configuration.getParallelism());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_SALT_LENGTH, configuration.getSaltLength());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_HASH_LENGTH, configuration.getHashLength());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_MAX_MEMORY, configuration.getMaxMemory());
            assertEquals(Argon2PasswordEncoderConfigurationProperties.DEFAULT_MAX_ITERATIONS, configuration.getMaxIterations());
        }
    }

    @Test
    void propertiesBindToTheConfiguration() {
        Map<String, Object> properties = Map.of(
            "micronaut.security.password.argon2.memory", 512,
            "micronaut.security.password.argon2.iterations", 3,
            "micronaut.security.password.argon2.parallelism", 2,
            "micronaut.security.password.argon2.salt-length", 24,
            "micronaut.security.password.argon2.hash-length", 48,
            "micronaut.security.password.argon2.max-memory", 1024,
            "micronaut.security.password.argon2.max-iterations", 5
        );
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            Argon2PasswordEncoderConfiguration configuration = context.getBean(Argon2PasswordEncoderConfiguration.class);

            assertEquals(512, configuration.getMemory());
            assertEquals(3, configuration.getIterations());
            assertEquals(2, configuration.getParallelism());
            assertEquals(24, configuration.getSaltLength());
            assertEquals(48, configuration.getHashLength());
            assertEquals(1024, configuration.getMaxMemory());
            assertEquals(5, configuration.getMaxIterations());
        }
    }

    @Test
    void theEncoderBeanUsesTheConfiguration() {
        Map<String, Object> properties = Map.of(
            "micronaut.security.password.argon2.memory", 512,
            "micronaut.security.password.argon2.iterations", 3,
            "micronaut.security.password.argon2.parallelism", 2
        );
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            PasswordEncoder encoder = context.getBean(PasswordEncoder.class);

            assertInstanceOf(Argon2PasswordEncoder.class, encoder);
            String encoded = encoder.encode("correct horse battery staple");
            assertTrue(encoded.startsWith("$argon2id$v=19$m=512,t=3,p=2$"));
            assertTrue(encoder.matches("correct horse battery staple", encoded));
        }
    }

    @Test
    void theEncoderBeanFailsToStartWithAnInvalidConfiguration() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("micronaut.security.password.argon2.parallelism", 0))) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class, () -> context.getBean(PasswordEncoder.class));

            assertTrue(e.getMessage().contains("micronaut.security.password.argon2.parallelism must be between 1 and 255 but was 0"));
        }
    }
}
