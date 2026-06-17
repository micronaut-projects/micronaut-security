package io.micronaut.security.ojdbc.extensions;

import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ATTRIBUTE_NAMES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DEFAULT_ATTRIBUTE_NAMES;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.END_USER_CONTEXT_ATTRIBUTE_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
}
