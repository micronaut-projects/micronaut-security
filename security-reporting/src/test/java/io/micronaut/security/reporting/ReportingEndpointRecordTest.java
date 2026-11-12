package io.micronaut.security.reporting;

import io.micronaut.core.beans.BeanIntrospection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportingEndpointRecordTest {
    private static final URI URL = URI.create("/csp/report");

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ReportingEndpointRecord.class));
    }

    @Test
    void acceptsAStructuredFieldsDictionaryKey() {
        ReportingEndpointRecord record = new ReportingEndpointRecord("csp", URL);

        assertEquals("csp", record.getName());
        assertEquals(URL, record.getUrl());
    }

    @ParameterizedTest
    @ValueSource(strings = {"*", "csp-report", "csp_report.v1", "*.wildcard*", "a0"})
    void acceptsEveryCharacterOfTheKeyGrammar(String name) {
        assertDoesNotThrow(() -> new ReportingEndpointRecord(name, URL));
    }

    @ParameterizedTest
    @ValueSource(strings = {"my endpoint", "end\"point", "Csp", "0csp", "-csp", "", "csp,network", "csp=x"})
    void rejectsNamesOutsideTheKeyGrammar(String name) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> new ReportingEndpointRecord(name, URL));

        assertTrue(e.getMessage().contains("\"" + name + "\""), e.getMessage());
        assertTrue(e.getMessage().contains(ReportingEndpointNames.KEY_GRAMMAR), e.getMessage());
    }

    @Test
    void rejectsANullName() {
        assertThrows(IllegalArgumentException.class, () -> new ReportingEndpointRecord(null, URL));
    }
}
