package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Base64UtilsTest {

    private static final String GUARD_MESSAGE = "Invalid Base64 padding";
    private static final String SIXTY_FOUR_A = "A".repeat(64);

    private static final String HUNDRED_TWENTY_EIGHT_A = "A".repeat(128);

    /**
     * Tail forms listed by Calif for the Java4Shell write-up, with X and Y any Base64 character.
     */
    private static final List<String> CALIF_TAILS = List.of("=", "==", "A=", "A==", "AB=", "===");

    static Stream<String> java4ShellPayloads() {
        // No prefix, one AVX-512 block (64), and the JDK 17 trigger length (128).
        return Stream.of("", SIXTY_FOUR_A, HUNDRED_TWENTY_EIGHT_A)
                .flatMap(prefix -> CALIF_TAILS.stream().map(tail -> prefix + tail));
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void java4ShellPayloadIsRejectedByTheGuard(String src) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src));
        assertEquals(GUARD_MESSAGE, e.getMessage());
    }

    @Test
    void publishedProofOfConceptPayloadsAreRejectedByTheGuard() {
        IllegalArgumentException jdk21 = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(SIXTY_FOUR_A + "="));
        assertEquals(GUARD_MESSAGE, jdk21.getMessage());
        IllegalArgumentException jdk17 = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(HUNDRED_TWENTY_EIGHT_A + "="));
        assertEquals(GUARD_MESSAGE, jdk17.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ABCDE=", "ABCDEF=", "AA==AAAA="})
    void otherPaddingThatDoesNotCompleteTheFinalUnitIsRejectedByTheGuard(String src) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src));
        assertEquals(GUARD_MESSAGE, e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "QUJD",                          // no padding
        "QUI=",                          // one padding character
        "QQ==",                          // two padding characters
        "dXNlcjpwYXNzd29yZA==",          // user:password
        "QQ",                            // unpadded, length not a multiple of four
        "QUI",                           // unpadded, length not a multiple of four
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",     // 64 characters
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQ==", // 68 characters, padded
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABC="  // 68 characters, padded
    })
    void wellFormedInputDecodesLikeTheJdk(String src) {
        assertArrayEquals(Base64.getDecoder().decode(src), Base64Utils.decode(src));
    }

    @Test
    void decodesObviousFixture() {
        assertEquals("user:password", new String(Base64Utils.decode("dXNlcjpwYXNzd29yZA=="), StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @ValueSource(strings = {"QU*D", "QU D", "QUJ\n", "QUJ-", "QUJ_", "QQ=A"})
    void illegalCharactersAreStillRejectedByTheJdk(String src) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src));
        assertNotEquals(GUARD_MESSAGE, e.getMessage());
    }

    @Test
    void unpaddedInputOfInvalidLengthIsLeftToTheJdk() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(SIXTY_FOUR_A + "A"));
        assertNotEquals(GUARD_MESSAGE, e.getMessage());
    }

    @Test
    void acceptsExactlyTheInputsTheJdkAccepts() {
        // Exhaustive over a small alphabet: the guard must never reject input the JDK would accept.
        for (String src : allStrings("AQ=", 8)) {
            byte[] expected = jdkDecodeOrNull(src);
            if (expected == null) {
                assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src), src);
            } else {
                assertArrayEquals(expected, Base64Utils.decode(src), src);
            }
        }
    }

    private static byte[] jdkDecodeOrNull(String src) {
        try {
            return Base64.getDecoder().decode(src);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<String> allStrings(String alphabet, int maxLength) {
        List<String> result = new ArrayList<>();
        result.add("");
        int start = 0;
        for (int length = 1; length <= maxLength; length++) {
            int end = result.size();
            for (int i = start; i < end; i++) {
                for (char c : alphabet.toCharArray()) {
                    result.add(result.get(i) + c);
                }
            }
            start = end;
        }
        return result;
    }
}
