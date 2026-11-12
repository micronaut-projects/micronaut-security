package io.micronaut.security.scim.server.filter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultScimFilterParserTest {
    private final ScimFilterParser parser = new DefaultScimFilterParser();

    @Test
    void parsesRfcValuePathAndLogicalPrecedence() {
        ScimFilter filter = parser.parse(
            "userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")");

        ScimFilter.Logical and = assertInstanceOf(ScimFilter.Logical.class, filter);
        assertEquals(ScimFilter.LogicalOperator.AND, and.operator());
        ScimFilter.Comparison userType = assertInstanceOf(ScimFilter.Comparison.class, and.left());
        assertEquals("userType", userType.attributePath());
        assertEquals(ScimFilter.ComparisonOperator.EQUAL, userType.operator());
        assertEquals("Employee", userType.value().value());
        ScimFilter.Logical or = assertInstanceOf(ScimFilter.Logical.class, and.right());
        assertEquals(ScimFilter.LogicalOperator.OR, or.operator());
    }

    @Test
    void parsesComplexAttributeValueFilter() {
        ScimFilter filter = parser.parse("emails[type eq \"work\" and value co \"@example.com\"]");

        ScimFilter.ValuePath valuePath = assertInstanceOf(ScimFilter.ValuePath.class, filter);
        assertEquals("emails", valuePath.attributePath());
        assertInstanceOf(ScimFilter.Logical.class, valuePath.filter());
    }

    @Test
    void rejectsUnquotedStringsAndTrailingContent() {
        assertThrows(ScimFilterException.class, () -> parser.parse("userName eq bjensen"));
        assertThrows(ScimFilterException.class, () -> parser.parse("userName pr unexpected"));
        assertThrows(ScimFilterException.class, () -> parser.parse("userName eq 01"));
        assertThrows(ScimFilterException.class, () -> parser.parse("invalid/path pr"));
    }
}
