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
        "userPassword;lang-en, userPassword;binary, false"
    })
    void matchesAttributeTypesWithoutMatchingUnrelatedNames(String attribute, String excluded, boolean expected) {
        assertEquals(expected, LdapAttributeUtils.matchesExclusion(attribute, excluded));
    }
}
