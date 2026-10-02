package io.micronaut.security.password.argon2;

import io.micronaut.context.exceptions.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2PasswordEncoderTest {
    private static final String PASSWORD = "correct horse battery staple";

    @Test
    void formatsAndVerifiesWithTheSharedPolicy() {
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(new Argon2PasswordEncoderConfigurationProperties(), new StubArgon2HashFunction());
        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        assertTrue(encoder.matches(PASSWORD, encoded));
        assertFalse(encoder.matches(PASSWORD + "!", encoded));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "\t", "\n"})
    void rejectsBlankPasswords(String blank) {
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(new Argon2PasswordEncoderConfigurationProperties(), new StubArgon2HashFunction());

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(blank));
        assertFalse(encoder.matches(blank, encoder.encode(PASSWORD)));
        assertFalse(encoder.matches(PASSWORD, blank));
    }

    @Test
    void rejectsInvalidAndUnsafeEncodedPasswords() {
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(new Argon2PasswordEncoderConfigurationProperties(), new StubArgon2HashFunction());
        String encoded = encoder.encode(PASSWORD);

        assertFalse(encoder.matches(PASSWORD, "invalid"));
        assertFalse(encoder.matches(PASSWORD, encoded.replace("m=19456", "m=262145")));
        assertFalse(encoder.matches(PASSWORD, encoded.replace("t=2", "t=11")));
        assertFalse(encoder.matches(PASSWORD, encoded.replace("m=19456", "m=7")));
    }

    @Test
    void rejectsMemoryOutsideTheConfiguredRange() {
        Argon2PasswordEncoderConfigurationProperties configuration = new Argon2PasswordEncoderConfigurationProperties();
        configuration.setMemory(7);
        assertThrows(ConfigurationException.class, () -> new Argon2PasswordEncoder(configuration, new StubArgon2HashFunction()));

        configuration.setMemory(262145);
        assertThrows(ConfigurationException.class, () -> new Argon2PasswordEncoder(configuration, new StubArgon2HashFunction()));
    }

    @Test
    void configurationPropertiesRoundTrip() {
        Argon2PasswordEncoderConfigurationProperties configuration = new Argon2PasswordEncoderConfigurationProperties();
        configuration.setMemory(512);
        configuration.setIterations(3);
        configuration.setParallelism(2);
        configuration.setSaltLength(24);
        configuration.setHashLength(48);
        configuration.setMaxMemory(1024);
        configuration.setMaxIterations(5);

        assertEquals(512, configuration.getMemory());
        assertEquals(3, configuration.getIterations());
        assertEquals(2, configuration.getParallelism());
        assertEquals(24, configuration.getSaltLength());
        assertEquals(48, configuration.getHashLength());
        assertEquals(1024, configuration.getMaxMemory());
        assertEquals(5, configuration.getMaxIterations());
    }

    /** Only exercises the shared policy; concrete implementation tests cover real Argon2 hashing. */
    private static final class StubArgon2HashFunction implements Argon2HashFunction {
        @Override
        public byte[] hash(String rawPassword, byte[] salt, int memory, int iterations, int parallelism, int hashLength) {
            byte[] password = rawPassword.getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[hashLength];
            for (int i = 0; i < result.length; i++) {
                result[i] = (byte) (password[i % password.length] ^ salt[i % salt.length]);
            }
            return result;
        }

        @Override
        public String getName() {
            return "stub";
        }
    }
}
