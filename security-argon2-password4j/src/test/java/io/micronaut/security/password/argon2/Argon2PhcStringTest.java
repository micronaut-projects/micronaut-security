package io.micronaut.security.password.argon2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class Argon2PhcStringTest {

    // Test vector from the Argon2 reference implementation (phc-winner-argon2, src/test.c)
    private static final String REFERENCE = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
    private static final byte[] REFERENCE_SALT = "somesalt".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REFERENCE_HASH = HexFormat.of().parseHex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
    private static final String PARAMETERS = "$argon2id$v=19$m=8,t=1,p=1$";

    @Test
    void parsesAConformingString() {
        Argon2PhcString phc = Argon2PhcString.parse(REFERENCE);

        assertNotNull(phc);
        assertEquals(65536, phc.memory());
        assertEquals(2, phc.iterations());
        assertEquals(1, phc.parallelism());
        assertArrayEquals(REFERENCE_SALT, phc.salt());
        assertArrayEquals(REFERENCE_HASH, phc.hash());
    }

    @Test
    void formatsAConformingString() {
        assertEquals(REFERENCE, Argon2PhcString.format(65536, 2, 1, REFERENCE_SALT, REFERENCE_HASH));
    }

    @Test
    void formatsWithoutBase64Padding() {
        String formatted = Argon2PhcString.format(8, 1, 1, new byte[16], new byte[32]);

        // 16 bytes are 22 unpadded Base64 characters and 32 bytes are 43
        assertEquals(PARAMETERS + "A".repeat(22) + "$" + "A".repeat(43), formatted);
    }

    @Test
    void acceptsTheLargestDecimalsAllowedByTheGrammar() {
        Argon2PhcString phc = Argon2PhcString.parse("$argon2id$v=19$m=9999999999,t=9999999999,p=255$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc");

        assertNotNull(phc);
        assertEquals(9_999_999_999L, phc.memory());
        assertEquals(9_999_999_999L, phc.iterations());
        assertEquals(255, phc.parallelism());
    }

    @ParameterizedTest
    @CsvSource({
        // Base64 characters of the salt, Base64 characters of the hash, salt bytes, hash bytes
        "11, 16, 8, 12",
        "64, 86, 48, 64",
    })
    void acceptsTheShortestAndLongestSaltAndHash(int saltCharacters, int hashCharacters, int saltLength, int hashLength) {
        Argon2PhcString phc = Argon2PhcString.parse(PARAMETERS + "A".repeat(saltCharacters) + "$" + "A".repeat(hashCharacters));

        assertNotNull(phc);
        assertEquals(saltLength, phc.salt().length);
        assertEquals(hashLength, phc.hash().length);
    }

    @ParameterizedTest
    @CsvSource({
        // Base64 characters of the salt, Base64 characters of the hash
        "10, 43",
        "65, 43",
        "66, 43",
        "22, 15",
        "22, 87",
        "22, 88",
    })
    void rejectsASaltOrHashOutsideTheAllowedLengths(int saltCharacters, int hashCharacters) {
        assertNull(Argon2PhcString.parse(PARAMETERS + "A".repeat(saltCharacters) + "$" + "A".repeat(hashCharacters)));
    }

    @Test
    void parsesWhatItFormats() {
        byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] hash = {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13};

        Argon2PhcString phc = Argon2PhcString.parse(Argon2PhcString.format(19456, 3, 4, salt, hash));

        assertNotNull(phc);
        assertEquals(19456, phc.memory());
        assertEquals(3, phc.iterations());
        assertEquals(4, phc.parallelism());
        assertArrayEquals(salt, phc.salt());
        assertArrayEquals(hash, phc.hash());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "$",
        "password",
        // missing leading separator
        "argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // other Argon2 variants
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2d$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$ARGON2ID$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // missing or unsupported version
        "$argon2id$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=20$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // parameters missing or out of order
        "$argon2id$v=19$t=2,m=65536,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,p=1,t=2$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // unsupported optional parameters
        "$argon2id$v=19$m=65536,t=2,p=1,keyid=AAAA$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=1,data=AAAA$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // decimals that are zero, signed, have leading zeros or are not decimals
        "$argon2id$v=19$m=0,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=0,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=0$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=065536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=02,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=01$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=-65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=+65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=64k,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // decimals with too many digits
        "$argon2id$v=19$m=10000000000,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=10000000000,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=1000$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // parallelism above 255
        "$argon2id$v=19$m=65536,t=2,p=256$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=999$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // missing salt or hash
        "$argon2id$v=19$m=65536,t=2,p=1",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$",
        "$argon2id$v=19$m=65536,t=2,p=1$$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // salt whose length is not a valid Base64 length
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQAA$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // salt whose trailing bits are not zero
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHR$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // salt with padding or with characters outside the Base64 alphabet
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ=$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhb-_$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhb Q$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        // hash whose length is not a valid Base64 length
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPcAA",
        // hash whose trailing bits are not zero
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPd",
        // hash with padding
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc=",
        // surrounding whitespace
        " $argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc\n",
        // trailing fields
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc$AAAA",
    })
    void rejectsANonConformingString(String encoded) {
        assertNull(Argon2PhcString.parse(encoded));
    }
}
