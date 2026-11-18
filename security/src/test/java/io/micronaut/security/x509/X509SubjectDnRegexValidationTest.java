package io.micronaut.security.x509;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509SubjectDnRegexValidationTest {

    private static final String PROPERTY = X509ConfigurationProperties.PREFIX + ".subject-dn-regex";

    private static final String ZERO_CAPTURING_GROUPS = "CN=.*?(?:,|$)";
    private static final String TWO_CAPTURING_GROUPS = "(CN)=(.*?)(?:,|$)";
    private static final String INVALID_SYNTAX = "CN=(.*?";

    @ParameterizedTest
    @ValueSource(strings = {ZERO_CAPTURING_GROUPS, TWO_CAPTURING_GROUPS, INVALID_SYNTAX})
    void applicationContextFailsToStartWithAnInvalidSubjectDnRegex(String regex) {
        BeanInstantiationException e = assertThrows(BeanInstantiationException.class, () -> ApplicationContext.run(configuration(regex)).close());

        assertConfigurationExceptionNamesPropertyAndValue(e, regex);
    }

    @ParameterizedTest
    @ValueSource(strings = {ZERO_CAPTURING_GROUPS, TWO_CAPTURING_GROUPS, INVALID_SYNTAX})
    void serverFailsToStartWithAnInvalidSubjectDnRegex(String regex) {
        BeanInstantiationException e = assertThrows(BeanInstantiationException.class, () -> ApplicationContext.run(EmbeddedServer.class, configuration(regex)).close());

        assertConfigurationExceptionNamesPropertyAndValue(e, regex);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            X509ConfigurationProperties.DEFAULT_SUBJECT_DN_REGEX,
            "OU=(.*?)(?:,|$)",
            "CN=([^,]+)(?:,|$)"
    })
    void applicationContextStartsWithASubjectDnRegexWithExactlyOneCapturingGroup(String regex) {
        try (ApplicationContext ctx = ApplicationContext.run(configuration(regex))) {
            assertNotNull(ctx.getBean(X509AuthenticationFetcher.class));
            assertEquals(regex, ctx.getBean(X509Configuration.class).getSubjectDnRegex());
        }
    }

    private static Map<String, Object> configuration(String regex) {
        return Map.of(
                X509ConfigurationProperties.PREFIX + ".enabled", true,
                PROPERTY, regex
        );
    }

    private static void assertConfigurationExceptionNamesPropertyAndValue(Throwable t, String regex) {
        Throwable current = t;
        while (current != null && !(current instanceof ConfigurationException)) {
            current = current.getCause();
        }
        assertNotNull(current, "expected a ConfigurationException in the cause chain of " + t);
        assertTrue(current.getMessage().contains(PROPERTY));
        assertTrue(current.getMessage().contains(regex));
    }
}
