package io.micronaut.security.ojdbc.extensions;

import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import oracle.sql.json.OracleJsonValue;
import org.junit.jupiter.api.Test;

import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonUtilsTest {

    private static final OracleJsonFactory JSON_FACTORY = new OracleJsonFactory();

    @Test
    void requireJsonObjectReturnsJsonObject() {
        OracleJsonObject value = JSON_FACTORY.createObject();
        value.put("name", "Sherlock");

        OracleJsonObject result = JsonUtils.requireJsonObject("claims", value);

        assertSame(value, result);
        assertEquals("Sherlock", result.getString("name"));
    }

    @Test
    void requireJsonObjectRejectsNullValue() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> JsonUtils.requireJsonObject("claims", null));

        assertEquals("Value of \"claims\" is null", exception.getMessage());
    }

    @Test
    void requireJsonObjectRejectsNonObjectValue() {
        OracleJsonValue value = JSON_FACTORY.createJsonTextValue(new StringReader("[\"admin\"]"));

        OracleJsonException exception = assertThrows(OracleJsonException.class,
                () -> JsonUtils.requireJsonObject("claims", value));

        assertEquals("Value of claims is a ARRAY. A JSON object is required.", exception.getMessage());
    }
}
