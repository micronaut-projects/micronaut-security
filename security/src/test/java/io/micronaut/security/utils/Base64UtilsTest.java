package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Base64UtilsTest {

    private static final String GUARD_MESSAGE = "Invalid Base64 padding";
    private static final String SIXTY_FOUR_A = "A".repeat(64);

    @ParameterizedTest
    @ValueSource(strings = {"", "QQ==", "QUI=", "QUJD", "dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzOndvcmQ="})
    void validInputDecodesLikeTheJdk(String src) {
        assertArrayEquals(Base64.getDecoder().decode(src), Base64Utils.decode(src));
    }

    @ParameterizedTest
    @ValueSource(strings = {"=", "==", "===", "A=", "A==", "AB=", "ABCDE=", "ABCDEF=", "AA==AAAA="})
    void paddingThatDoesNotCompleteTheFinalUnitIsRejectedByTheGuard(String src) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src));
        assertEquals(GUARD_MESSAGE, e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"=", "==", "===", "A=", "A==", "AB="})
    void java4ShellTailsAfterAFullIntrinsicBlockAreRejectedByTheGuard(String tail) {
        // 64 characters fill one AVX-512 block; the vulnerable path handles the short padded tail.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(SIXTY_FOUR_A + tail));
        assertEquals(GUARD_MESSAGE, e.getMessage());
    }

    @Test
    void paddedTailThatCompletesItsUnitAfterAFullIntrinsicBlockIsDecoded() {
        String src = SIXTY_FOUR_A + "ABC=";
        assertArrayEquals(Base64.getDecoder().decode(src), Base64Utils.decode(src));
    }

    @Test
    void publishedProofOfConceptPayloadsAreRejectedByTheGuard() {
        for (String src : List.of(SIXTY_FOUR_A + "=", "A".repeat(128) + "=")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(src));
            assertEquals(GUARD_MESSAGE, e.getMessage());
        }
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
