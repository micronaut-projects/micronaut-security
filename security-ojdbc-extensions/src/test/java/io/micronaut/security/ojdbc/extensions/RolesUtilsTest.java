package io.micronaut.security.ojdbc.extensions;

import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RolesUtilsTest {

    @Test
    void getPrefixedRolesReturnsRolesWithoutPrefix() {
        Authentication authentication = Authentication.build("sherlock", Arrays.asList(
                null,
                "ORA_DBA",
                "ORA_DBA",
                "ORA_ REPORTER ",
                "ORA_ANALYST",
                "ORA_",
                "ROLE_ADMIN",
                " ORA_IGNORED"));

        Set<String> roles = RolesUtils.getPrefixedRoles("ORA_", authentication);

        assertEquals(Set.of("DBA", "REPORTER", "ANALYST"), roles);
    }

    @Test
    void getPrefixedRolesReturnsEmptySetWhenNoRolesMatch() {
        assertTrue(RolesUtils.getPrefixedRoles("ORA_", Authentication.build("sherlock")).isEmpty());
        assertTrue(RolesUtils.getPrefixedRoles("ORA_", Authentication.build("sherlock", List.of("ROLE_ADMIN", "ROLE_USER"))).isEmpty());
        assertTrue(RolesUtils.getPrefixedRoles("ORA_", Authentication.build("sherlock", List.of("ORA_", "ORA_   "))).isEmpty());
    }
}
