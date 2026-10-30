package io.micronaut.security.ldap.context;

import org.junit.jupiter.api.Test;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttributesConvertibleValuesTest {

    @Test
    void singleValuedAttributeContainingCommaIsNotSplitWhenReadAsList() {
        Attributes attributes = new BasicAttributes(true);
        attributes.put("cn", "club-chess,payroll-admins");
        AttributesConvertibleValues values = new AttributesConvertibleValues(attributes);

        Optional<List> list = values.get("cn", List.class);

        assertTrue(list.isPresent());
        assertEquals(Collections.singletonList("club-chess,payroll-admins"), list.get());
    }

    @Test
    void multiValuedAttributeIsReadAsListOfEveryValue() {
        Attributes attributes = new BasicAttributes(true);
        BasicAttribute cn = new BasicAttribute("cn");
        cn.add("Sales,Marketing");
        cn.add("Engineering");
        attributes.put(cn);
        AttributesConvertibleValues values = new AttributesConvertibleValues(attributes);

        Optional<List> list = values.get("cn", List.class);

        assertTrue(list.isPresent());
        assertEquals(2, list.get().size());
        assertTrue(list.get().contains("Sales,Marketing"));
        assertTrue(list.get().contains("Engineering"));
    }

    @Test
    void singleValuedAttributeIsReadAsString() {
        Attributes attributes = new BasicAttributes(true);
        attributes.put("cn", "Sales,Marketing");
        AttributesConvertibleValues values = new AttributesConvertibleValues(attributes);

        assertEquals(Optional.of("Sales,Marketing"), values.get("cn", String.class));
    }

    @Test
    void singleValuedAttributeContainingCommaIsNotSplitWhenReadAsArray() {
        Attributes attributes = new BasicAttributes(true);
        attributes.put("cn", "club-chess,payroll-admins");
        AttributesConvertibleValues values = new AttributesConvertibleValues(attributes);

        Optional<String[]> array = values.get("cn", String[].class);

        assertTrue(array.isPresent());
        assertArrayEquals(new String[] {"club-chess,payroll-admins"}, array.get());
    }

    @Test
    void missingAttributeIsEmpty() {
        AttributesConvertibleValues values = new AttributesConvertibleValues(new BasicAttributes(true));

        assertFalse(values.get("cn", List.class).isPresent());
    }
}
