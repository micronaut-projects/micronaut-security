package io.micronaut.security.password.argon2;

import io.micronaut.context.exceptions.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the encoder directly, without the validation interceptor that guards the bean.
 */
class Argon2PasswordEncoderTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String SALT_AND_HASH = "$" + "A".repeat(22) + "$" + "A".repeat(43);

    @Test
    void encodesWithTheDefaultParameters() {
        Argon2PasswordEncoder encoder = encoder(new Argon2PasswordEncoderConfigurationProperties());

        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        Argon2PhcString phc = Argon2PhcString.parse(encoded);
        assertNotNull(phc);
        assertEquals(16, phc.salt().length);
        assertEquals(32, phc.hash().length);
        assertTrue(encoder.matches(PASSWORD, encoded));
    }

    @Test
    void encodesWithTheConfiguredParameters() {
        Argon2PasswordEncoder encoder = encoder(configuration(256, 3, 2, 8, 12));

        String encoded = encoder.encode(PASSWORD);

        assertTrue(encoded.startsWith("$argon2id$v=19$m=256,t=3,p=2$"));
        Argon2PhcString phc = Argon2PhcString.parse(encoded);
        assertNotNull(phc);
        assertEquals(8, phc.salt().length);
        assertEquals(12, phc.hash().length);
        assertTrue(encoder.matches(PASSWORD, encoded));
    }

    @ParameterizedTest
    @CsvSource({
        // Test vectors from the Argon2 reference implementation (phc-winner-argon2, src/test.c)
        "password, '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc'",
        "password, '$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4'",
        "password, '$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc'",
        "differentpassword, '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94'",
        "password, '$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw'",
        // Hashes created by Spring Security's Argon2PasswordEncoder 6.3.4 (Bouncy Castle 1.84)
        "correct horse battery staple, '$argon2id$v=19$m=16384,t=2,p=1$oD4J6tHQEKFFoGSw8uyJyg$PaHHvg2gl1OKYaPxIveAoFJ2jqi5s8ovKOtXSaLte+0'",
        "correct horse battery staple, '$argon2id$v=19$m=4096,t=3,p=1$059jsX4xde0gyoqQEHNujA$d7/sLyLHhNNctYoEMpiqNx8W0rv7EmWgDhRpyRUCpwI'",
        "pässwörd-密码-🔐, '$argon2id$v=19$m=16384,t=2,p=1$9Qn2FOuD/EI7hi34pX2m2w$uSEl4qIaL4M+Jbs7Gvrt7YxY+rVOat+MwRlrU0yE9k4'",
    })
    void matchesHashesCreatedByOtherImplementations(String password, String encoded) {
        Argon2PasswordEncoder encoder = encoder(new Argon2PasswordEncoderConfigurationProperties());

        assertTrue(encoder.matches(password, encoded));
        assertFalse(encoder.matches(password + "!", encoded));
    }

    @Test
    void matchesAHashCreatedWithParametersOtherThanTheConfiguredOnes() {
        String encoded = encoder(configuration(512, 3, 2, 24, 48)).encode(PASSWORD);
        Argon2PasswordEncoder encoder = encoder(configuration(256, 1, 1, 16, 32));

        assertTrue(encoder.matches(PASSWORD, encoded));
        assertFalse(encoder.matches("Tr0ub4dor&3", encoded));
    }

    @Test
    void matchesAHashCreatedWithTheMaximumMemoryAndIterations() {
        Argon2PasswordEncoderConfigurationProperties highest = configuration(1024, 4, 1, 16, 32);
        highest.setMaxMemory(1024);
        highest.setMaxIterations(4);
        String encoded = encoder(highest).encode(PASSWORD);
        Argon2PasswordEncoderConfigurationProperties configuration = configuration(256, 1, 1, 16, 32);
        configuration.setMaxMemory(1024);
        configuration.setMaxIterations(4);

        assertTrue(encoder(configuration).matches(PASSWORD, encoded));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "m=1025,t=1,p=1",
        "m=2147483648,t=1,p=1",
        "m=9999999999,t=1,p=1",
    })
    void doesNotMatchAHashThatDeclaresMoreMemoryThanTheMaximum(String parameters) {
        Argon2PasswordEncoderConfigurationProperties configuration = configuration(256, 1, 1, 16, 32);
        configuration.setMaxMemory(1024);

        assertFalse(encoder(configuration).matches(PASSWORD, "$argon2id$v=19$" + parameters + SALT_AND_HASH));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "m=256,t=5,p=1",
        "m=256,t=2147483648,p=1",
        "m=256,t=9999999999,p=1",
    })
    void doesNotMatchAHashThatDeclaresMoreIterationsThanTheMaximum(String parameters) {
        Argon2PasswordEncoderConfigurationProperties configuration = configuration(256, 1, 1, 16, 32);
        configuration.setMaxIterations(4);

        assertFalse(encoder(configuration).matches(PASSWORD, "$argon2id$v=19$" + parameters + SALT_AND_HASH));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "m=7,t=1,p=1",
        "m=15,t=1,p=2",
        "m=2039,t=1,p=255",
    })
    void doesNotMatchAHashThatDeclaresLessMemoryThanItsParallelismRequires(String parameters) {
        Argon2PasswordEncoder encoder = encoder(configuration(256, 1, 1, 16, 32));

        assertFalse(encoder.matches(PASSWORD, "$argon2id$v=19$" + parameters + SALT_AND_HASH));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        PASSWORD,
        "not-an-encoded-password",
        "$argon2i$v=19$m=256,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
    })
    void doesNotMatchAnEncodedPasswordItCannotParse(String encoded) {
        Argon2PasswordEncoder encoder = encoder(configuration(256, 1, 1, 16, 32));

        assertFalse(encoder.matches(PASSWORD, encoded));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "\t", "\n"})
    void encodeRejectsABlankPassword(String blank) {
        Argon2PasswordEncoder encoder = encoder(configuration(256, 1, 1, 16, 32));

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(blank));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "\t", "\n"})
    void doesNotMatchABlankPasswordOrABlankEncodedPassword(String blank) {
        Argon2PasswordEncoder encoder = encoder(configuration(256, 1, 1, 16, 32));
        String encoded = encoder.encode(PASSWORD);

        assertFalse(encoder.matches(blank, encoded));
        assertFalse(encoder.matches(PASSWORD, blank));
    }

    @ParameterizedTest
    @CsvSource({
        // property, memory, iterations, parallelism, salt length, hash length
        "parallelism, 2048, 1, 0, 16, 32",
        "parallelism, 2048, 1, 256, 16, 32",
        "memory, 7, 1, 1, 16, 32",
        "memory, 15, 1, 2, 16, 32",
        "memory, 262145, 1, 1, 16, 32",
        "iterations, 256, 0, 1, 16, 32",
        "iterations, 256, 11, 1, 16, 32",
        "salt-length, 256, 1, 1, 7, 32",
        "salt-length, 256, 1, 1, 49, 32",
        "hash-length, 256, 1, 1, 16, 11",
        "hash-length, 256, 1, 1, 16, 65",
    })
    void rejectsAnInvalidConfiguration(String property, int memory, int iterations, int parallelism, int saltLength, int hashLength) {
        Argon2PasswordEncoderConfigurationProperties configuration = configuration(memory, iterations, parallelism, saltLength, hashLength);

        ConfigurationException e = assertThrows(ConfigurationException.class, () -> encoder(configuration));

        assertTrue(e.getMessage().startsWith("micronaut.security.password.argon2." + property + " must be between "));
    }

    @ParameterizedTest
    @CsvSource({
        // memory, iterations, parallelism, salt length, hash length
        "8, 1, 1, 8, 12",
        "2040, 10, 255, 48, 64",
    })
    void acceptsAConfigurationAtTheLimits(int memory, int iterations, int parallelism, int saltLength, int hashLength) {
        Argon2PasswordEncoder encoder = encoder(configuration(memory, iterations, parallelism, saltLength, hashLength));

        assertNotNull(encoder);
    }

    private static Argon2PasswordEncoderConfigurationProperties configuration(int memory, int iterations, int parallelism, int saltLength, int hashLength) {
        Argon2PasswordEncoderConfigurationProperties configuration = new Argon2PasswordEncoderConfigurationProperties();
        configuration.setMemory(memory);
        configuration.setIterations(iterations);
        configuration.setParallelism(parallelism);
        configuration.setSaltLength(saltLength);
        configuration.setHashLength(hashLength);
        return configuration;
    }

    private static Argon2PasswordEncoder encoder(Argon2PasswordEncoderConfiguration configuration) {
        return new Argon2PasswordEncoder(configuration, new Password4jArgon2HashFunction());
    }
}
