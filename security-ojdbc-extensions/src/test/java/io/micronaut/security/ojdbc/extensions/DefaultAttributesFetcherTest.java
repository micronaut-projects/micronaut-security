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

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.END_USER_CONTEXT_ATTRIBUTE_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAttributesFetcherTest {

    private static final OracleJsonFactory JSON_FACTORY = new OracleJsonFactory();

    private final DefaultAttributesFetcher fetcher = new DefaultAttributesFetcher(JSON_FACTORY);

    @Test
    void fetchAttributesMergesFixedAndPrefixedAuthenticationAttributes() {
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
        parameters.put(AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER, "ATTR_");

        Authentication authentication = Authentication.build("sherlock", List.of(
                "ATTR_{\"hr.employee\":{\"level\":3,\"country\":\"US\"}}",
                "ATTR_{\"app.preferences\":{\"theme\":\"dark\"}}",
                "ROLE_ADMIN",
                "ATTR_{}"));

        Map<String, OracleJsonObject> attributes = fetcher.fetchAttributes(parameters, authentication);

        assertEquals(Set.of("hr.employee", "app.audit", "app.preferences"), attributes.keySet());

        OracleJsonObject employee = attributes.get("hr.employee");
        assertEquals("Sales", employee.getString("department"));
        assertEquals(3, employee.getInt("level"));
        assertEquals("US", employee.getString("country"));

        assertEquals("fixed", attributes.get("app.audit").getString("source"));
        assertEquals("dark", attributes.get("app.preferences").getString("theme"));
    }

    @Test
    void fetchAttributesReturnsEmptyMapWhenNoAttributesAreConfiguredOrMatched() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(AUTHORITY_ATTRIBUTE_PREFIX_PARAMETER, "ATTR_");

        Authentication authentication = Authentication.build("sherlock", List.of("ROLE_ADMIN"));

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
}
