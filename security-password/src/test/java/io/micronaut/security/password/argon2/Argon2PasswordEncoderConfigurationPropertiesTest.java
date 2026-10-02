package io.micronaut.security.password.argon2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.constraints.ConstraintValidatorContext;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class Argon2PasswordEncoderConfigurationPropertiesTest {
    private static final String PREFIX = Argon2PasswordEncoderConfigurationProperties.PREFIX;

    @Test
    void theDefaultConfigurationIsValid(Validator validator) {
        assertEquals(Set.of(), violations(validator, new Argon2PasswordEncoderConfigurationProperties()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("configurationsAtTheLimits")
    void acceptsValuesAtTheLimits(String description, Consumer<Argon2PasswordEncoderConfigurationProperties> customizer, Validator validator) {
        Argon2PasswordEncoderConfigurationProperties properties = new Argon2PasswordEncoderConfigurationProperties();
        customizer.accept(properties);

        assertEquals(Set.of(), violations(validator, properties));
    }

    static Stream<Arguments> configurationsAtTheLimits() {
        return Stream.of(
            configuration("lowest parallelism", c -> c.setParallelism(1)),
            configuration("highest parallelism", c -> c.setParallelism(255)),
            configuration("lowest memory", c -> c.setMemory(8)),
            configuration("lowest memory for the parallelism", c -> {
                c.setParallelism(2);
                c.setMemory(16);
            }),
            configuration("memory equal to max-memory", c -> c.setMemory(262144)),
            configuration("memory equal to a lowered max-memory", c -> {
                c.setMaxMemory(512);
                c.setMemory(512);
            }),
            configuration("lowest iterations", c -> c.setIterations(1)),
            configuration("iterations equal to max-iterations", c -> c.setIterations(10)),
            configuration("shortest salt", c -> c.setSaltLength(8)),
            configuration("longest salt", c -> c.setSaltLength(48)),
            configuration("shortest hash", c -> c.setHashLength(12)),
            configuration("longest hash", c -> c.setHashLength(64))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidConfigurations")
    void rejectsValuesOutsideTheLimits(String violation, Consumer<Argon2PasswordEncoderConfigurationProperties> customizer, Validator validator) {
        Argon2PasswordEncoderConfigurationProperties properties = new Argon2PasswordEncoderConfigurationProperties();
        customizer.accept(properties);

        assertEquals(Set.of(violation), violations(validator, properties));
    }

    static Stream<Arguments> invalidConfigurations() {
        return Stream.of(
            configuration("parallelism must be greater than or equal to 1", c -> c.setParallelism(0)),
            configuration("parallelism must be less than or equal to 255", c -> c.setParallelism(256)),
            configuration("memory must be between 8 and 262144", c -> c.setMemory(7)),
            configuration("memory must be between 16 and 262144", c -> {
                c.setParallelism(2);
                c.setMemory(15);
            }),
            configuration("memory must be between 8 and 262144", c -> c.setMemory(262145)),
            configuration("memory must be between 8 and 512", c -> {
                c.setMaxMemory(512);
                c.setMemory(1024);
            }),
            configuration("iterations must be greater than or equal to 1", c -> c.setIterations(0)),
            configuration("iterations must be less than or equal to 10", c -> c.setIterations(11)),
            configuration("iterations must be less than or equal to 2", c -> {
                c.setMaxIterations(2);
                c.setIterations(3);
            }),
            configuration("saltLength must be greater than or equal to 8", c -> c.setSaltLength(7)),
            configuration("saltLength must be less than or equal to 48", c -> c.setSaltLength(49)),
            configuration("hashLength must be greater than or equal to 12", c -> c.setHashLength(11)),
            configuration("hashLength must be less than or equal to 64", c -> c.setHashLength(65))
        );
    }

    @Test
    void reportsEveryCostOutsideItsLimits(Validator validator) {
        Argon2PasswordEncoderConfigurationProperties properties = new Argon2PasswordEncoderConfigurationProperties();
        properties.setMemory(7);
        properties.setIterations(11);

        assertEquals(
            Set.of("memory must be between 8 and 262144", "iterations must be less than or equal to 10"),
            violations(validator, properties));
    }

    @Test
    void anInvalidParallelismDoesNotLowerTheMinimumMemory(Validator validator) {
        Argon2PasswordEncoderConfigurationProperties properties = new Argon2PasswordEncoderConfigurationProperties();
        properties.setParallelism(0);
        properties.setMemory(7);

        assertEquals(
            Set.of("parallelism must be greater than or equal to 1", "memory must be between 8 and 262144"),
            violations(validator, properties));
    }

    @Test
    void theCostsValidatorAcceptsNull() {
        ConstraintValidatorContext unused = (ConstraintValidatorContext) Proxy.newProxyInstance(
            ConstraintValidatorContext.class.getClassLoader(),
            new Class<?>[] {ConstraintValidatorContext.class},
            (proxy, method, args) -> {
                throw new AssertionError("The context must not be used for a null value");
            });

        assertTrue(new ValidArgon2CostsValidator().isValid(null, AnnotationValue.builder(ValidArgon2Costs.class).build(), unused));
    }

    @Test
    void theApplicationContextBindsTheConfiguration() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            PREFIX + ".memory", 512,
            PREFIX + ".iterations", 3,
            PREFIX + ".parallelism", 2,
            PREFIX + ".salt-length", 24,
            PREFIX + ".hash-length", 48,
            PREFIX + ".max-memory", 1024,
            PREFIX + ".max-iterations", 5
        ))) {
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

    @ParameterizedTest
    @MethodSource("invalidProperties")
    void theApplicationContextFailsToStartWithAnInvalidConfiguration(String property, int value, String violation) {
        Map<String, Object> properties = Map.of(PREFIX + "." + property, value);

        // no bean is requested: starting the context is enough to detect the invalid configuration
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class, () -> ApplicationContext.run(properties));

        assertTrue(exception.getMessage().contains(violation), exception.getMessage());
    }

    static Stream<Arguments> invalidProperties() {
        return Stream.of(
            Arguments.of("parallelism", 0, "parallelism - must be greater than or equal to 1"),
            Arguments.of("memory", 7, "memory - must be between 8 and 262144"),
            Arguments.of("iterations", 11, "iterations - must be less than or equal to 10")
        );
    }

    private static Set<String> violations(Validator validator, Argon2PasswordEncoderConfigurationProperties properties) {
        return validator.validate(properties).stream()
            .map(Argon2PasswordEncoderConfigurationPropertiesTest::describe)
            .collect(Collectors.toSet());
    }

    private static String describe(ConstraintViolation<?> violation) {
        return violation.getPropertyPath() + " " + violation.getMessage();
    }

    private static Arguments configuration(String description, Consumer<Argon2PasswordEncoderConfigurationProperties> customizer) {
        return Arguments.of(description, customizer);
    }
}
