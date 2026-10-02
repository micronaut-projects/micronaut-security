package io.micronaut.security.password.argon2.bouncycastle;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.NonUniqueBeanException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiplePasswordEncodersTest {
    private static final String SPEC_NAME = "MultiplePasswordEncodersTest";
    private static final String PASSWORD = "correct horse battery staple";

    @Test
    void theArgon2EncoderIsSelectedByTheNameOfItsImplementation() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", SPEC_NAME))) {
            assertThrows(NonUniqueBeanException.class, () -> context.getBean(PasswordEncoder.class));

            PasswordEncoder argon2 = context.getBean(PasswordEncoder.class, Qualifiers.byName("bouncycastle"));
            String encoded = argon2.encode(PASSWORD);
            assertTrue(encoded.startsWith("$argon2id$v=19$"));
            assertTrue(argon2.matches(PASSWORD, encoded));

            PasswordEncoder legacy = context.getBean(PasswordEncoder.class, Qualifiers.byName(LegacyPasswordEncoder.NAME));
            assertInstanceOf(LegacyPasswordEncoder.class, legacy);
        }
    }

    @Test
    void theArgon2EncoderNeedsNoQualifierWhenItIsTheOnlyEncoder() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertEquals(
                context.getBean(PasswordEncoder.class, Qualifiers.byName("bouncycastle")),
                context.getBean(PasswordEncoder.class));
        }
    }

    /** Stands in for a second encoder in the application. It is a test fixture, not a real encoder. */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    @Named(LegacyPasswordEncoder.NAME)
    static class LegacyPasswordEncoder implements PasswordEncoder {
        static final String NAME = "legacy";

        @Override
        public String encode(String rawPassword) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean matches(String rawPassword, String encodedPassword) {
            return false;
        }
    }
}
