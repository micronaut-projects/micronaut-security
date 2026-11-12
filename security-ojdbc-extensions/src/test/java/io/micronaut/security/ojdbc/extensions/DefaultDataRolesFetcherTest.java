package io.micronaut.security.ojdbc.extensions;

import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.spi.OracleResourceProvider;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DATA_ROLES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ROLE_PREFIX_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DefaultDataRolesFetcherTest {

    private final DefaultDataRolesFetcher fetcher = new DefaultDataRolesFetcher();

    @Test
    void fetchDataRolesMergesFixedAndPrefixedAuthenticationRoles() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(DATA_ROLES_PARAMETER, "FIXED_REPORTING, FIXED_DBA, , FIXED_DBA");
        parameters.put(ROLE_PREFIX_PARAMETER, "ORA_");

        Authentication authentication = Authentication.build("sherlock", Arrays.asList(
                "ORA_ANALYST",
                "ORA_ REPORTER ",
                "ORA_DBA",
                "ORA_DBA",
                "ORA_",
                "ROLE_ADMIN"));

        Collection<String> dataRoles = fetcher.fetchDataRoles(parameters, authentication);

        Set<String> expected = Set.of("FIXED_REPORTING", "FIXED_DBA", "ANALYST", "REPORTER", "DBA");
        assertEquals(expected.size(), dataRoles.size());
        assertEquals(expected, Set.copyOf(dataRoles));
    }

    @Test
    void fetchDataRolesReturnsNullWhenNoRolesAreConfiguredOrMatched() {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new HashMap<>();
        parameters.put(ROLE_PREFIX_PARAMETER, "ORA_");

        Authentication authentication = Authentication.build("sherlock", Set.of("ROLE_ADMIN", "ORA_", "ORA_   "));

        assertNull(fetcher.fetchDataRoles(Map.of(), Authentication.build("sherlock")));
        assertNull(fetcher.fetchDataRoles(parameters, authentication));
    }

    @Test
    void mergeDataRolesReturnsNullWhenEverySetIsNullOrEmpty() {
        assertNull(DefaultDataRolesFetcher.mergeDataRoles(null, Set.of()));
    }

    @Test
    void mergeDataRolesCombinesNonEmptySets() {
        Set<String> dataRoles = DefaultDataRolesFetcher.mergeDataRoles(
                Set.of("REPORTING", "ANALYST"),
                null,
                Set.of("ANALYST", "DBA"));

        assertEquals(Set.of("REPORTING", "ANALYST", "DBA"), dataRoles);
    }
}
