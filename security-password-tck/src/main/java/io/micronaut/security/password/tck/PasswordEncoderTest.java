/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.password.tck;

import io.micronaut.security.password.PasswordEncoder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
@SuppressWarnings({
    "java:S5960", // this is a TCK test class, so assertions are expected
    "java:S2068", // the passwords in this class are test fixtures
})
class PasswordEncoderTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final int THREADS = 4;

    @Test
    void encodedPasswordIsNotBlank(PasswordEncoder passwordEncoder) {
        assertFalse(passwordEncoder.encode(PASSWORD).isBlank());
    }

    @Test
    void encodedPasswordDoesNotContainTheRawPassword(PasswordEncoder passwordEncoder) {
        String encoded = passwordEncoder.encode(PASSWORD);
        assertNotEquals(PASSWORD, encoded);
        assertFalse(encoded.contains(PASSWORD));
    }

    @Test
    void encodingTheSamePasswordTwiceProducesDifferentEncodings(PasswordEncoder passwordEncoder) {
        String first = passwordEncoder.encode(PASSWORD);
        String second = passwordEncoder.encode(PASSWORD);
        assertNotEquals(first, second);
        assertTrue(passwordEncoder.matches(PASSWORD, first));
        assertTrue(passwordEncoder.matches(PASSWORD, second));
    }

    @Test
    void matchesReturnsTrueForTheEncodedPassword(PasswordEncoder passwordEncoder) {
        assertTrue(passwordEncoder.matches(PASSWORD, passwordEncoder.encode(PASSWORD)));
    }

    @Test
    void matchesReturnsFalseForADifferentPassword(PasswordEncoder passwordEncoder) {
        assertFalse(passwordEncoder.matches("Tr0ub4dor&3", passwordEncoder.encode(PASSWORD)));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', ignoreLeadingAndTrailingWhitespace = false, value = {
        "password|Password",
        "password|PASSWORD",
        "password| password",
        "password|password ",
        "pass word|password",
        "pass word|pass  word",
    })
    void caseAndWhitespaceAreSignificant(String password, String other, PasswordEncoder passwordEncoder) {
        String encoded = passwordEncoder.encode(password);
        assertTrue(passwordEncoder.matches(password, encoded));
        assertFalse(passwordEncoder.matches(other, encoded));
    }

    @ParameterizedTest
    @CsvSource({
        "pässwörd, passwörd",
        "密码安全, 口令安全",
        "пароль, пapoль", // Cyrillic letters and their Latin lookalikes
        "🔐🔑, 🔐🗝",
    })
    void nonAsciiCharactersAreSignificant(String password, String other, PasswordEncoder passwordEncoder) {
        String encoded = passwordEncoder.encode(password);
        assertTrue(passwordEncoder.matches(password, encoded));
        assertFalse(passwordEncoder.matches(other, encoded));
    }

    @Test
    void longPasswordsAreNotTruncated(PasswordEncoder passwordEncoder) {
        String prefix = "a".repeat(200);
        String password = prefix + "1";
        String encoded = passwordEncoder.encode(password);
        assertTrue(passwordEncoder.matches(password, encoded));
        assertFalse(passwordEncoder.matches(prefix + "2", encoded));
        assertFalse(passwordEncoder.matches(prefix, encoded));
    }

    @Test
    void passwordsAreNotTruncatedAtANulCharacter(PasswordEncoder passwordEncoder) {
        String password = "abc\u0000def";
        String encoded = passwordEncoder.encode(password);
        assertTrue(passwordEncoder.matches(password, encoded));
        assertFalse(passwordEncoder.matches("abc\u0000xyz", encoded));
        assertFalse(passwordEncoder.matches("abc", encoded));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        PASSWORD,
        "not-an-encoded-password",
        "$",
        "$$$$$",
        ":",
        ":::",
        "{noop}" + PASSWORD,
    })
    void matchesReturnsFalseForAMalformedEncodedPassword(String malformed, PasswordEncoder passwordEncoder) {
        assertFalse(passwordEncoder.matches(PASSWORD, malformed));
    }

    @Test
    void matchesReturnsFalseForATruncatedEncodedPassword(PasswordEncoder passwordEncoder) {
        String encoded = passwordEncoder.encode(PASSWORD);
        assertFalse(passwordEncoder.matches(PASSWORD, encoded.substring(0, encoded.length() / 2)));
        assertFalse(passwordEncoder.matches(PASSWORD, encoded.substring(0, encoded.length() - 1)));
    }

    @Test
    void encoderIsSafeForConcurrentUse(PasswordEncoder passwordEncoder) {
        List<Callable<boolean[]>> tasks = new ArrayList<>();
        for (int i = 0; i < THREADS * 2; i++) {
            String password = PASSWORD + i;
            String other = PASSWORD + (i + 1);
            tasks.add(() -> {
                String encoded = passwordEncoder.encode(password);
                return new boolean[] {passwordEncoder.matches(password, encoded), passwordEncoder.matches(other, encoded)};
            });
        }
        try (ExecutorService executor = Executors.newFixedThreadPool(THREADS)) {
            for (Future<boolean[]> result : assertDoesNotThrow(() -> executor.invokeAll(tasks))) {
                boolean[] matches = assertDoesNotThrow(() -> result.get());
                assertTrue(matches[0]);
                assertFalse(matches[1]);
            }
        }
    }
}
