package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HeaderValuePrefixUtilsTest {

    @Test
    void prefixIsComparedIgnoringCase() {
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("Bearer x", "Bearer"));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("bearer x", "Bearer"));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("BEARER x", "bearer"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearerx", "Bearer", "Bear", "", "Bearer\tx", " Bearer x", "x Bearer y", "Basic x"})
    void prefixMustBeAtTheStartAndFollowedByASpace(String headerValue) {
        assertNull(HeaderValuePrefixUtils.removePrefix(headerValue, "Bearer"));
    }

    @Test
    void onlyOneSpaceIsRemoved() {
        assertEquals("", HeaderValuePrefixUtils.removePrefix("Bearer ", "Bearer"));
        assertEquals(" x", HeaderValuePrefixUtils.removePrefix("Bearer  x", "Bearer"));
        assertEquals("x y", HeaderValuePrefixUtils.removePrefix("Bearer x y", "Bearer"));
    }

    @Test
    void prefixEndingWithASpaceIsNotFollowedByAnotherSpace() {
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("Bearer x", "Bearer "));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("bearer x", "Bearer "));
        assertEquals("", HeaderValuePrefixUtils.removePrefix("Bearer ", "Bearer "));
        assertNull(HeaderValuePrefixUtils.removePrefix("Bearer", "Bearer "));
        assertNull(HeaderValuePrefixUtils.removePrefix("Bearerx", "Bearer "));
    }

    @Test
    void aPrefixMadeOfASpaceOnlyRemovesThatSpace() {
        assertEquals("x", HeaderValuePrefixUtils.removePrefix(" x", " "));
        assertNull(HeaderValuePrefixUtils.removePrefix("x", " "));
        assertEquals(" x", HeaderValuePrefixUtils.addPrefix("x", " "));
    }

    @Test
    void emptyPrefixReturnsTheWholeValue() {
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("x", null));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("x", ""));
        assertEquals("", HeaderValuePrefixUtils.removePrefix("", ""));
    }

    @Test
    void lookAlikeCharactersAreNotFoldedThroughUpperCase() {
        // long s and dotless i upper-case to S and I
        assertNull(HeaderValuePrefixUtils.removePrefix("Ba\u017F\u0131c x", "Basic"));
        // the Kelvin sign lower-cases to k
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("To\u212Aen x", "Token"));
        // capital I with dot above lower-cases to i
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("Bas\u0130c x", "Basic"));
        // non-ASCII letters in the prefix are compared ignoring case
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("T\u00D6K\u00C9N x", "T\u00F6k\u00E9n"));
    }

    @Test
    void addPrefixSeparatesThePrefixAndTheTokenWithOneSpace() {
        assertEquals("Bearer x", HeaderValuePrefixUtils.addPrefix("x", "Bearer"));
        assertEquals("Bearer x", HeaderValuePrefixUtils.addPrefix("x", "Bearer "));
    }

    @Test
    void addPrefixReturnsTheTokenAloneForAnEmptyPrefix() {
        assertEquals("x", HeaderValuePrefixUtils.addPrefix("x", null));
        assertEquals("x", HeaderValuePrefixUtils.addPrefix("x", ""));
    }
}
