package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HeaderValuePrefixUtilsTest {

    @Test
    void prefixIsComparedIgnoringCase() {
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("Bearer x", "Bearer"));
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("bearer x", "Bearer"));
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("BEARER x", "bearer"));
    }

    @Test
    void prefixMustBeAtTheStartAndFollowedByASpace() {
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bearerx", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bearer", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bear", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bearer\tx", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix(" Bearer x", "Bearer"));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Basic x", "Bearer"));
    }

    @Test
    void onlyOneSpaceIsRemoved() {
        assertEquals(Optional.of(""), HeaderValuePrefixUtils.removePrefix("Bearer ", "Bearer"));
        assertEquals(Optional.of(" x"), HeaderValuePrefixUtils.removePrefix("Bearer  x", "Bearer"));
        assertEquals(Optional.of("x y"), HeaderValuePrefixUtils.removePrefix("Bearer x y", "Bearer"));
    }

    @Test
    void prefixEndingWithASpaceIsNotFollowedByAnotherSpace() {
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("Bearer x", "Bearer "));
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("bearer x", "Bearer "));
        assertEquals(Optional.of(""), HeaderValuePrefixUtils.removePrefix("Bearer ", "Bearer "));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bearer", "Bearer "));
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Bearerx", "Bearer "));
    }

    @Test
    void emptyPrefixReturnsTheWholeValue() {
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("x", null));
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("x", ""));
        assertEquals(Optional.of(""), HeaderValuePrefixUtils.removePrefix("", ""));
    }

    @Test
    void lookAlikeCharactersAreNotFoldedThroughUpperCase() {
        // long s and dotless i upper-case to S and I
        assertEquals(Optional.empty(), HeaderValuePrefixUtils.removePrefix("Baſıc x", "Basic"));
        // the Kelvin sign lower-cases to k
        assertEquals(Optional.of("x"), HeaderValuePrefixUtils.removePrefix("ToKen x", "Token"));
    }
}
