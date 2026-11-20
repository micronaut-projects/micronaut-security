package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HeaderValuePrefixUtilsTest {

    @Test
    void prefixIsComparedIgnoringCase() {
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("Bearer x", "Bearer"));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("bearer x", "Bearer"));
        assertEquals("x", HeaderValuePrefixUtils.removePrefix("BEARER x", "bearer"));
    }

    @Test
    void prefixMustBeAtTheStartAndFollowedByASpace() {
        assertNull(HeaderValuePrefixUtils.removePrefix("Bearerx", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix("Bearer", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix("Bear", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix("", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix("Bearer\tx", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix(" Bearer x", "Bearer"));
        assertNull(HeaderValuePrefixUtils.removePrefix("Basic x", "Bearer"));
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
