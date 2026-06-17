package io.micronaut.security.ojdbc.extensions;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContextHolder;
import oracle.jdbc.EndUserSecurityContext;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ATTRIBUTE_NAMES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_ID_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DEFAULT_ATTRIBUTE_NAMES;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DEFAULT_ROLE_PREFIX;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ROLE_PREFIX_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.TOKEN_URL_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MicronautEndUserSecurityContextProviderTest {

    private static final OracleJsonFactory JSON_FACTORY = new OracleJsonFactory();
    private static final String DATABASE_ACCESS_TOKEN = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.";
    private static final String END_USER_TOKEN = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.";

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rolePrefixDefaultsToOracleDataRolePrefix() {
        assertEquals(DEFAULT_ROLE_PREFIX, ROLE_PREFIX_PARAMETER.defaultValue());
    }

    @Test
    void attributeNamesDefaultsToOracleContextAttributes() {
        assertEquals(DEFAULT_ATTRIBUTE_NAMES, ATTRIBUTE_NAMES_PARAMETER.defaultValue());
    }

    @Test
    void getEndUserSecurityContextReturnsNullWhenAuthenticationIsMissing() {
        RecordingDatabaseAccessTokenFetcher databaseAccessTokenFetcher = new RecordingDatabaseAccessTokenFetcher();
        RecordingDataRolesFetcher dataRolesFetcher = new RecordingDataRolesFetcher();
        RecordingAttributesFetcher attributesFetcher = new RecordingAttributesFetcher();
        MicronautEndUserSecurityContextProvider provider = new MicronautEndUserSecurityContextProvider(
                databaseAccessTokenFetcher,
                dataRolesFetcher,
                attributesFetcher);

        assertNull(provider.getEndUserSecurityContext(Map.of()));
        assertFalse(databaseAccessTokenFetcher.called);
        assertFalse(dataRolesFetcher.called);
        assertFalse(attributesFetcher.called);
    }

    @Test
    void getEndUserSecurityContextCreatesContextWithTokenOnlyWhenRolesAndAttributesAreNull() {
        RecordingDatabaseAccessTokenFetcher databaseAccessTokenFetcher = new RecordingDatabaseAccessTokenFetcher();
        RecordingDataRolesFetcher dataRolesFetcher = new RecordingDataRolesFetcher();
        RecordingAttributesFetcher attributesFetcher = new RecordingAttributesFetcher();
        MicronautEndUserSecurityContextProvider provider = new MicronautEndUserSecurityContextProvider(
                databaseAccessTokenFetcher,
                dataRolesFetcher,
                attributesFetcher);
        Authentication authentication = Authentication.build("sherlock", List.of("ROLE_DETECTIVE"));
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                TOKEN_URL_PARAMETER, "https://example.com/token");

        EndUserSecurityContext context = withSecurityContext(authentication, END_USER_TOKEN,
                () -> provider.getEndUserSecurityContext(parameters));

        assertSame(parameters, databaseAccessTokenFetcher.parameters);
        assertSame(parameters, dataRolesFetcher.parameters);
        assertSame(parameters, attributesFetcher.parameters);
        assertSame(authentication, dataRolesFetcher.authentication);
        assertSame(authentication, attributesFetcher.authentication);
        assertArrayEquals(DATABASE_ACCESS_TOKEN.toCharArray(), context.databaseAccessToken());
        assertTrue(context.endUserToken().isPresent());
        assertArrayEquals(END_USER_TOKEN.toCharArray(), context.endUserToken().get());
        assertTrue(context.dataRoles().isEmpty());
        assertTrue(context.attributes().isEmpty());
    }

    @Test
    void getEndUserSecurityContextCreatesContextWithNameWhenSecurityTokenIsMissing() {
        RecordingDatabaseAccessTokenFetcher databaseAccessTokenFetcher = new RecordingDatabaseAccessTokenFetcher();
        RecordingDataRolesFetcher dataRolesFetcher = new RecordingDataRolesFetcher();
        RecordingAttributesFetcher attributesFetcher = new RecordingAttributesFetcher();
        MicronautEndUserSecurityContextProvider provider = new MicronautEndUserSecurityContextProvider(
                databaseAccessTokenFetcher,
                dataRolesFetcher,
                attributesFetcher);
        Authentication authentication = Authentication.build("sherlock", List.of("ROLE_DETECTIVE"));
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                TOKEN_URL_PARAMETER, "https://example.com/token");

        EndUserSecurityContext context = withSecurityContext(authentication, null,
                () -> provider.getEndUserSecurityContext(parameters));

        assertSame(parameters, databaseAccessTokenFetcher.parameters);
        assertSame(parameters, dataRolesFetcher.parameters);
        assertSame(parameters, attributesFetcher.parameters);
        assertSame(authentication, dataRolesFetcher.authentication);
        assertSame(authentication, attributesFetcher.authentication);
        assertArrayEquals(DATABASE_ACCESS_TOKEN.toCharArray(), context.databaseAccessToken());
        assertTrue(context.endUserToken().isEmpty());
        assertTrue(context.endUserName().isPresent());
        assertEquals("sherlock", context.endUserName().get());
        assertTrue(context.dataRoles().isEmpty());
        assertTrue(context.attributes().isEmpty());
    }

    @Test
    void getEndUserSecurityContextAddsDataRolesAndAttributesWhenPresent() {
        RecordingDatabaseAccessTokenFetcher databaseAccessTokenFetcher = new RecordingDatabaseAccessTokenFetcher();
        RecordingDataRolesFetcher dataRolesFetcher = new RecordingDataRolesFetcher();
        dataRolesFetcher.dataRoles = List.of("REPORTING", "DBA");
        RecordingAttributesFetcher attributesFetcher = new RecordingAttributesFetcher();
        OracleJsonObject attributeValues = JSON_FACTORY.createObject();
        attributeValues.put("department", "Sales");
        attributesFetcher.attributes = Map.of("hr.employee", attributeValues);
        MicronautEndUserSecurityContextProvider provider = new MicronautEndUserSecurityContextProvider(
                databaseAccessTokenFetcher,
                dataRolesFetcher,
                attributesFetcher);
        Authentication authentication = Authentication.build("sherlock", List.of("ROLE_DETECTIVE"));
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = Map.of(
                TOKEN_URL_PARAMETER, "https://example.com/token",
                CLIENT_ID_PARAMETER, "database-client");

        EndUserSecurityContext context = withSecurityContext(authentication, END_USER_TOKEN,
                () -> provider.getEndUserSecurityContext(parameters));

        assertEquals(Set.of("REPORTING", "DBA"), context.dataRoles());
        assertEquals(Set.of("hr.employee"), context.attributes().keySet());
        assertEquals("Sales", context.attributes().get("hr.employee").getString("department"));
    }

    private static EndUserSecurityContext withSecurityContext(Authentication authentication,
                                                             String token,
                                                             ContextSupplier supplier) {
        HttpRequest<?> request = HttpRequest.GET("/employees");
        return ServerRequestContext.with(request, (Supplier<EndUserSecurityContext>) () -> {
            SecurityContextHolder.getSecurityContext()
                    .withAuthentication(authentication);
            if (token != null) {
                SecurityContextHolder.getSecurityContext()
                        .withToken(token);
            }
            return supplier.get();
        });
    }

    @FunctionalInterface
    private interface ContextSupplier {
        EndUserSecurityContext get();
    }

    private static final class RecordingDatabaseAccessTokenFetcher implements DatabaseAccessTokenFetcher {
        boolean called;
        Map<OracleResourceProvider.Parameter, CharSequence> parameters;

        @Override
        public String fetchDatabaseAccessToken(Map<OracleResourceProvider.Parameter, CharSequence> parameters) {
            called = true;
            this.parameters = parameters;
            return DATABASE_ACCESS_TOKEN;
        }
    }

    private static final class RecordingDataRolesFetcher implements DataRolesFetcher {
        boolean called;
        Map<OracleResourceProvider.Parameter, CharSequence> parameters;
        Authentication authentication;
        Collection<String> dataRoles;

        @Override
        public Collection<String> fetchDataRoles(Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                 Authentication authentication) {
            called = true;
            this.parameters = parameters;
            this.authentication = authentication;
            return dataRoles;
        }
    }

    private static final class RecordingAttributesFetcher implements AttributesFetcher {
        boolean called;
        Map<OracleResourceProvider.Parameter, CharSequence> parameters;
        Authentication authentication;
        Map<String, OracleJsonObject> attributes;

        @Override
        public Map<String, OracleJsonObject> fetchAttributes(Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                             Authentication authentication) {
            called = true;
            this.parameters = parameters;
            this.authentication = authentication;
            return attributes;
        }
    }
}
