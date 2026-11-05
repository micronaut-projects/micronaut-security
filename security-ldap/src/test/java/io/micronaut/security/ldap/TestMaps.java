package io.micronaut.security.ldap;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Java 8 replacement for {@code Map.of} in the LDAP tests.
 */
public final class TestMaps {

    private TestMaps() {
    }

    /**
     * @param keysAndValues Alternating keys and values
     * @return An unmodifiable map with the given entries
     */
    public static Map<String, Object> of(Object... keysAndValues) {
        if (keysAndValues.length % 2 != 0) {
            throw new IllegalArgumentException("Expected alternating keys and values");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put((String) keysAndValues[i], keysAndValues[i + 1]);
        }
        return Collections.unmodifiableMap(map);
    }
}
