/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.reporting;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = ReportingEndpointConfiguration.PREFIX + ".my-endpoint.url", value = "/reports")
@MicronautTest(startApplication = false)
class ReportingEndpointConfigurationTest {

    @Inject
    BeanContext beanContext;

    @Test
    void reportingEndpointViaConfiguration() {
        Collection<ReportingEndpoint> reportingEndpoints = beanContext.getBeansOfType(ReportingEndpoint.class);
        URI expectedUrl = URI.create("/reports");
        assertTrue(reportingEndpoints.stream()
            .anyMatch(re -> re.getName().equals("my-endpoint") && re.getUrl().equals(expectedUrl)));
        assertEquals("my-endpoint=\"/reports\"",
            new ReportingEndpoints(reportingEndpoints).toString());
    }

    @Test
    void acceptsAStructuredFieldsDictionaryKey() {
        try (ApplicationContext context = ApplicationContext.run(endpointProperty("csp"))) {
            List<String> names = context.getBeansOfType(ReportingEndpoint.class).stream()
                .map(ReportingEndpoint::getName)
                .toList();

            assertEquals(List.of("csp"), names);
        }
    }

    @Test
    void lowerCasesTheConfiguredName() {
        try (ApplicationContext context = ApplicationContext.run(endpointProperty("Csp"))) {
            Collection<ReportingEndpoint> endpoints = context.getBeansOfType(ReportingEndpoint.class);

            assertEquals(List.of("csp"), endpoints.stream().map(ReportingEndpoint::getName).toList());
            assertEquals("csp=\"/csp/report\"", new ReportingEndpoints(endpoints).toString());
        }
    }

    @Test
    void lowerCasesTheNameGivenToTheConstructor() {
        assertEquals("csp", new ReportingEndpointConfiguration("Csp").getName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"my endpoint", "end\"point"})
    void rejectsNamesOutsideTheKeyGrammar(String name) {
        ConfigurationException e = assertThrows(ConfigurationException.class,
            () -> new ReportingEndpointConfiguration(name));

        assertConfigurationMessageNamesTheProperty(e, name);
    }

    @Test
    void failsBeanCreationForANameOutsideTheKeyGrammar() {
        // Micronaut hyphenates most property keys ("my endpoint" becomes "my-endpoint"), but a
        // quote passes through verbatim and must be rejected when the bean is created.
        String name = "end\"point";
        try (ApplicationContext context = ApplicationContext.run(endpointProperty(name))) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class,
                () -> context.getBeansOfType(ReportingEndpoint.class));

            assertInstanceOf(ConfigurationException.class, e.getCause());
            assertConfigurationMessageNamesTheProperty((ConfigurationException) e.getCause(), name);
        }
    }

    private static void assertConfigurationMessageNamesTheProperty(ConfigurationException e, String name) {
        String expectedProperty = ReportingEndpointConfiguration.PREFIX + "." + name;
        assertTrue(e.getMessage().contains(expectedProperty), e.getMessage());
        assertTrue(e.getMessage().contains(ReportingEndpointNames.KEY_GRAMMAR), e.getMessage());
    }

    private static Map<String, Object> endpointProperty(String name) {
        return Map.of(ReportingEndpointConfiguration.PREFIX + "." + name + ".url", "/csp/report");
    }
}
