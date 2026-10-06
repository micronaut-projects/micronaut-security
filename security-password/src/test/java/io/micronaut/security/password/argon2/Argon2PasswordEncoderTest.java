package io.micronaut.security.password.argon2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
        Argon2PasswordEncoder encoder = encoder();
        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        assertTrue(encoder.matches(PASSWORD, encoded));
        assertFalse(encoder.matches(PASSWORD + "!", encoded));
    }

    // the invocation names leave the arguments out: test reports cannot represent an unpaired surrogate
    @ParameterizedTest(name = "[{index}]")
    @CsvSource({
        "\uD800, ?",
        "\uDC00, ?",
        "pass\uD800word, pass?word",
        "\uD800A, ?A",
    })
    void rejectsPasswordsWithAnUnpairedSurrogate(String malformed, String lookalike) {
        Argon2PasswordEncoder encoder = encoder();

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(malformed));
        // the stub hashes the UTF-8 bytes of the password, where an unpaired surrogate becomes '?'
        assertFalse(encoder.matches(malformed, encoder.encode(lookalike)));
    }

    @Test
    void rejectsAnEncodedPasswordThatIsNotAPhcString() {
        assertFalse(encoder().matches(PASSWORD, "invalid"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "m=262145,t=2,p=1", // more memory than the default max-memory
        "m=19456,t=11,p=1", // more iterations than the default max-iterations
        "m=7,t=2,p=1", // less memory than Argon2 requires
        "m=15,t=2,p=2", // less memory than Argon2 requires for the parallelism
    })
    void rejectsUnsafeHashParameters(String parameters) {
        Argon2PasswordEncoder encoder = encoder();
        String encoded = encoder.encode(PASSWORD);

        // the stub ignores the cost parameters, so only the limits can reject the password
        assertFalse(encoder.matches(PASSWORD, encoded.replace("m=19456,t=2,p=1", parameters)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "m=1025,t=1,p=1",
        "m=256,t=5,p=1",
    })
    void rejectsHashParametersAboveTheConfiguredLimits(String parameters) {
        Argon2PasswordEncoderConfigurationProperties configuration = new Argon2PasswordEncoderConfigurationProperties();
        configuration.setMemory(256);
        configuration.setIterations(1);
        configuration.setMaxMemory(1024);
        configuration.setMaxIterations(4);
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(configuration, new StubArgon2HashFunction());
        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoder.matches(PASSWORD, encoded.replace("m=256,t=1,p=1", "m=1024,t=4,p=1")));
        assertFalse(encoder.matches(PASSWORD, encoded.replace("m=256,t=1,p=1", parameters)));
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

    private static Argon2PasswordEncoder encoder() {
        return new Argon2PasswordEncoder(new Argon2PasswordEncoderConfigurationProperties(), new StubArgon2HashFunction());
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
