package io.micronaut.security.x509;

import io.micronaut.context.exceptions.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509UtilsTest {

    private static final String PROPERTY = X509ConfigurationProperties.PREFIX + ".subject-dn-regex";

    @ParameterizedTest
    @ValueSource(strings = {
            X509ConfigurationProperties.DEFAULT_SUBJECT_DN_REGEX,
            "OU=(.*?)(?:,|$)",
            "CN=([^,]+)(?:,|$)"
    })
    void regexWithExactlyOneCapturingGroupIsCompiled(String regex) {
        Pattern pattern = X509Utils.compileSubjectDnRegex(regex);

        assertNotNull(pattern);
        assertEquals(regex, pattern.pattern());
        assertEquals(1, pattern.matcher("").groupCount());
    }

    @Test
    void compiledPatternIsCaseInsensitive() {
        Pattern pattern = X509Utils.compileSubjectDnRegex(X509ConfigurationProperties.DEFAULT_SUBJECT_DN_REGEX);

        Matcher matcher = pattern.matcher("cn=alice,OU=Engineering,O=Example");

        assertTrue(matcher.find());
        assertEquals("alice", matcher.group(1));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "CN=.*?(?:,|$)",
            "(CN)=(.*?)(?:,|$)"
    })
    void regexWithoutExactlyOneCapturingGroupIsRejected(String regex) {
        ConfigurationException e = assertThrows(ConfigurationException.class, () -> X509Utils.compileSubjectDnRegex(regex));

        assertTrue(e.getMessage().contains(PROPERTY));
        assertTrue(e.getMessage().contains(regex));
        assertTrue(e.getMessage().contains("exactly one capturing group"));
    }

    @Test
    void invalidRegexIsRejected() {
        String regex = "CN=(.*?";

        ConfigurationException e = assertThrows(ConfigurationException.class, () -> X509Utils.compileSubjectDnRegex(regex));

        assertTrue(e.getMessage().contains(PROPERTY));
        assertTrue(e.getMessage().contains(regex));
        assertInstanceOf(PatternSyntaxException.class, e.getCause());
    }
}
