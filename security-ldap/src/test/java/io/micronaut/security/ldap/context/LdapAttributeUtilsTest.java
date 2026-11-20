package io.micronaut.security.ldap.context;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LdapAttributeUtilsTest {

    @ParameterizedTest
    @CsvSource({
        "userPassword, userPassword, true",
        "UsErPaSsWoRd;BiNaRy, userPassword, true",
        "userPassword;binary;lang-en, userPassword, true",
        "unicodePwd;binary, unicodePwd, true",
        "userPasswordHistory;binary, userPassword, false",
        "cn;lang-en, userPassword, false",
        "userPassword, userPassword;binary, false",
        "userPassword;BINARY, userPassword;binary, true",
        "userPassword;lang-en, userPassword;binary, false",
        "2.5.4.35, userPassword, true",
        "2.5.4.35;binary, userPassword, true",
        "userPassword;binary, 2.5.4.35, true",
        "1.2.840.113556.1.4.90;binary, unicodePwd, true",
        "unicodePwd;binary, 1.2.840.113556.1.4.90, true",
        "userPassword;binary;x-review, userPassword;x-review;binary, true",
        "userPassword;BINARY;X-REVIEW, 2.5.4.35;x-review;binary, true",
        "userPassword;binary;x-review, userPassword;binary, false",
        "userPassword;binary, userPassword;binary;x-review, false",
        "2.5.4.350;binary, userPassword, false"
    })
    void matchesAttributeTypesWithoutMatchingUnrelatedNames(String attribute, String excluded, boolean expected) {
        assertEquals(expected, LdapAttributeUtils.matchesExclusion(attribute, excluded));
    }
}
