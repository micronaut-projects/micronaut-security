package io.micronaut.security.ojdbc.extensions;

import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonArray;
import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ATTRIBUTE_NAMES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DEFAULT_ATTRIBUTE_NAMES;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.END_USER_CONTEXT_ATTRIBUTE_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAttributesFetcherTest {

    private static final OracleJsonFactory JSON_FACTORY = new OracleJsonFactory();

    private final DefaultAttributesFetcher fetcher = new DefaultAttributesFetcher(JSON_FACTORY);

    @Test
    void fetchAttributesMergesFixedAndNamedAuthenticationAttributes() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(END_USER_CONTEXT_ATTRIBUTE_PARAMETER, """
                {
                  "hr.employee": {
                    "department": "Sales",
                    "level": 2
                  },
                  "app.audit": {
                    "source": "fixed"
                  }
                }
                """);
        parameters.put(ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES, ORACLE_CONTEXT_ATTRIBUTES, MISSING_ATTRIBUTES, , OVERRIDE_ATTRIBUTES");

        Authentication authentication = Authentication.build("sherlock",
                List.of(
                        "IGNORED_CONTEXT_ROLE_{\"hr.employee\":{\"level\":5,\"country\":\"CA\"}}",
                        "ROLE_ADMIN"),
                Map.of(
                        "APP_ATTRIBUTES", Map.of(
                                "hr.employee", Map.of("level", 3, "country", "US"),
                                "app.preferences", Map.of("theme", "dark")),
                        "ORACLE_CONTEXT_ATTRIBUTES", """
                                {
                                  "hr.employee": {
                                    "level": 4,
                                    "region": "AMER"
                                  }
                                }
                                """,
                        "OVERRIDE_ATTRIBUTES", Map.of(
                                "app.preferences", Map.of("theme", "contrast")),
                        "unrelated", Map.of("ignored", true)));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        assertEquals(Set.of("hr.employee", "app.audit", "app.preferences"), attributes.keySet());

        OracleJsonObject employee = attributes.get("hr.employee");
        assertEquals("Sales", employee.getString("department"));
        assertEquals(4, employee.getInt("level"));
        assertEquals("US", employee.getString("country"));
        assertEquals("AMER", employee.getString("region"));

        assertEquals("fixed", attributes.get("app.audit").getString("source"));
        assertEquals("contrast", attributes.get("app.preferences").getString("theme"));
    }

    @Test
    void fetchAttributesUsesDefaultAttributeNames() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, DEFAULT_ATTRIBUTE_NAMES);
        Authentication authentication = Authentication.build("sherlock",
                Map.of(DEFAULT_ATTRIBUTE_NAMES, Map.of(
                        "hr.employee", Map.of("department", "Sales"))));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        assertEquals(Set.of("hr.employee"), attributes.keySet());
        assertEquals("Sales", attributes.get("hr.employee").getString("department"));
    }

    @Test
    void fetchAttributesConvertsSupportedMapValuesToOracleJsonValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        LocalDateTime localDateTime = LocalDateTime.of(2026, 6, 18, 10, 15, 30);
        OffsetDateTime offsetDateTime = OffsetDateTime.parse("2026-06-18T10:15:30+02:00");
        byte[] binaryValue = {1, 2, 3};
        Map<String, Object> contextAttributes = new LinkedHashMap<>();
        contextAttributes.put("nullValue", null);
        contextAttributes.put("oracleJsonValue", JSON_FACTORY.createString("existing"));
        contextAttributes.put("stringValue", new StringBuilder("Sherlock"));
        contextAttributes.put("integerValue", 7);
        contextAttributes.put("shortValue", (short) 8);
        contextAttributes.put("byteValue", (byte) 9);
        contextAttributes.put("longValue", 10L);
        contextAttributes.put("bigIntegerValue", BigInteger.valueOf(11));
        contextAttributes.put("bigDecimalValue", new BigDecimal("12.34"));
        contextAttributes.put("floatValue", 1.5f);
        contextAttributes.put("doubleValue", 2.5d);
        contextAttributes.put("booleanValue", true);
        contextAttributes.put("localDateTimeValue", localDateTime);
        contextAttributes.put("offsetDateTimeValue", offsetDateTime);
        contextAttributes.put("binaryValue", binaryValue);
        contextAttributes.put("mapValue", Map.of("nested", "value"));
        contextAttributes.put("collectionValue", List.of("first", 2, false));
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", contextAttributes)));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        OracleJsonObject context = attributes.get("app.context");
        assertTrue(context.isNull("nullValue"));
        assertEquals("existing", context.getString("oracleJsonValue"));
        assertEquals("Sherlock", context.getString("stringValue"));
        assertEquals(7, context.getInt("integerValue"));
        assertEquals(8, context.getInt("shortValue"));
        assertEquals(9, context.getInt("byteValue"));
        assertEquals(10L, context.getLong("longValue"));
        assertEquals(new BigDecimal("11"), context.getBigDecimal("bigIntegerValue"));
        assertEquals(new BigDecimal("12.34"), context.getBigDecimal("bigDecimalValue"));
        assertEquals(1.5d, context.getDouble("floatValue"), 0.000001d);
        assertEquals(2.5d, context.getDouble("doubleValue"), 0.000001d);
        assertTrue(context.getBoolean("booleanValue"));
        assertEquals(localDateTime, context.getLocalDateTime("localDateTimeValue"));
        assertEquals(offsetDateTime, context.getOffsetDateTime("offsetDateTimeValue"));
        assertArrayEquals(binaryValue, context.getBytes("binaryValue"));
        assertEquals("value", context.getObject("mapValue").getString("nested"));
        OracleJsonArray collectionValue = context.getArray("collectionValue");
        assertEquals("first", collectionValue.getString(0));
        assertEquals(2, collectionValue.getInt(1));
        assertFalse(collectionValue.getBoolean(2));
    }

    @Test
    void fetchAttributesReadsOracleJsonObjectAuthenticationAttributeValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        OracleJsonObject employee = JSON_FACTORY.createObject();
        employee.put("department", "Sales");
        OracleJsonObject contexts = JSON_FACTORY.createObject();
        contexts.put("hr.employee", employee);
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", contexts));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        assertEquals(Set.of("hr.employee"), attributes.keySet());
        assertEquals("Sales", attributes.get("hr.employee").getString("department"));
    }

    @Test
    void fetchAttributesReadsOracleJsonObjectContextValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        OracleJsonObject employee = JSON_FACTORY.createObject();
        employee.put("department", "Sales");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("hr.employee", employee)));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        assertEquals(Set.of("hr.employee"), attributes.keySet());
        assertEquals("Sales", attributes.get("hr.employee").getString("department"));
    }

    @Test
    void fetchAttributesReturnsEmptyMapWhenNoAttributesAreConfiguredOrMatched() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");

        Authentication authentication = Authentication.build("sherlock",
                List.of("APP_ATTRIBUTES", "ROLE_ADMIN"),
                Map.of("unrelated", "value"));

        assertTrue(fetcher.fetchAttributes(Map.of(), authentication).isEmpty());
        assertTrue(fetcher.fetchAttributes(parameters, authentication).isEmpty());
    }

    @Test
    void fetchAttributesRejectsContextValuesThatAreNotJsonObjects() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(END_USER_CONTEXT_ATTRIBUTE_PARAMETER, "{\"hr.employee\":\"not an object\"}");

        OracleJsonException exception = assertThrows(OracleJsonException.class,
                () -> fetcher.fetchAttributes(parameters, Authentication.build("sherlock")));

        assertEquals("Value of hr.employee within attributes configured by the endUserContextAttributes parameter is a STRING. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsAuthenticationAttributeValuesThatAreNotJsonObjects() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");

        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", "\"not an object\""));

        OracleJsonException exception = assertThrows(OracleJsonException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a STRING. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNullAuthenticationAttributeValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<String, Object> authenticationAttributes = new HashMap<>();
        authenticationAttributes.put("APP_ATTRIBUTES", null);
        Authentication authentication = Authentication.build("sherlock", authenticationAttributes);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is null. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsUnsupportedAuthenticationAttributeValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", new Object()));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a java.lang.Object. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNullContextNames() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<Object, Object> contexts = new HashMap<>();
        contexts.put(null, Map.of("department", "Sales"));
        Map<String, Object> authenticationAttributes = Map.of("APP_ATTRIBUTES", contexts);
        Authentication authentication = Authentication.build("sherlock", authenticationAttributes);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Key of authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is null. A String is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNonStringContextNames() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<Object, Object> contexts = Map.of(42, Map.of("department", "Sales"));
        Map<String, Object> authenticationAttributes = Map.of("APP_ATTRIBUTES", contexts);
        Authentication authentication = Authentication.build("sherlock", authenticationAttributes);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Key of authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a java.lang.Integer. A String is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNullContextValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<String, Object> contexts = new HashMap<>();
        contexts.put("app.context", null);
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", contexts));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is null. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsOracleJsonContextValuesThatAreNotObjects() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", JSON_FACTORY.createString("not an object"))));

        OracleJsonException exception = assertThrows(OracleJsonException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a STRING. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsUnsupportedContextValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", new Object())));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a java.lang.Object. A JSON object is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNullContextAttributeNames() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<Object, Object> contextAttributes = new HashMap<>();
        contextAttributes.put(null, "Sales");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", contextAttributes)));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Key of app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is null. A String is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsNonStringContextAttributeNames() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Map<Object, Object> contextAttributes = Map.of(42, "Sales");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", contextAttributes)));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Key of app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a java.lang.Integer. A String is required.",
                exception.getMessage());
    }

    @Test
    void fetchAttributesRejectsUnsupportedContextAttributeValues() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                ATTRIBUTE_NAMES_PARAMETER, "APP_ATTRIBUTES");
        Authentication authentication = Authentication.build("sherlock",
                Map.of("APP_ATTRIBUTES", Map.of("app.context", Map.of("unsupported", new Object()))));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> fetcher.fetchAttributes(parameters, authentication));

        assertEquals("Value of unsupported within app.context within authentication attribute APP_ATTRIBUTES configured by the attributeNames parameter is a java.lang.Object. A supported JSON value is required.",
                exception.getMessage());
    }
}
