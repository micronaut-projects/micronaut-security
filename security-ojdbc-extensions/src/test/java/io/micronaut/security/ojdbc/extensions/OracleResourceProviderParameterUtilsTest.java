package io.micronaut.security.ojdbc.extensions;

import oracle.jdbc.spi.OracleResourceProvider;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_ID_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.SCOPE_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.TOKEN_URL_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.OracleResourceProviderParameterUtils.optionalParameter;
import static io.micronaut.security.ojdbc.extensions.OracleResourceProviderParameterUtils.requiredParameter;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OracleResourceProviderParameterUtilsTest {

    @Test
    void optionalParameterReturnsNullWhenParameterIsAbsent() {
        assertNull(optionalParameter(Map.of(), SCOPE_PARAMETER));
    }

    @Test
    void optionalParameterReturnsConfiguredValueAsString() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                SCOPE_PARAMETER, new StringBuilder("https://database.example/.default"));

        assertEquals("https://database.example/.default", optionalParameter(parameters, SCOPE_PARAMETER));
    }

    @Test
    void optionalParameterReturnsBlankValueUnchanged() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(SCOPE_PARAMETER, "   ");

        assertEquals("   ", optionalParameter(parameters, SCOPE_PARAMETER));
    }

    @Test
    void requiredParameterReturnsConfiguredValueUnchanged() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                TOKEN_URL_PARAMETER, "  https://example.com/token  ");

        assertEquals("  https://example.com/token  ", requiredParameter(parameters, TOKEN_URL_PARAMETER));
    }

    @Test
    void requiredParameterRejectsMissingParameter() {
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> requiredParameter(Map.of(), CLIENT_ID_PARAMETER));

        assertEquals("Missing required provider parameter: clientId", exception.getMessage());
    }

    @Test
    void requiredParameterRejectsBlankParameter() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(CLIENT_ID_PARAMETER, "   ");

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> requiredParameter(parameters, CLIENT_ID_PARAMETER));

        assertEquals("Missing required provider parameter: clientId", exception.getMessage());
    }
}
