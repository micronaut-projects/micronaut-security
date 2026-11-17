package io.micronaut.security.ldap.context;

import org.junit.jupiter.api.Test;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultLdapSearchServiceTest {

    private final DefaultLdapSearchService service = new DefaultLdapSearchService();

    @Test
    void removingExcludedAttributesFromNullAttributesReturnsNull() throws NamingException {
        assertNull(service.removeExcludedAttributes(null, List.of("userPassword")));
    }

    @Test
    void excludedAttributesAreRemovedInPlaceIgnoringCaseOptionsAndNullEntries() throws NamingException {
        Attributes attributes = new BasicAttributes(true);
        attributes.put("cn", "Bernhard Riemann");
        attributes.put("UnicodePwd", "non-secret-test-fixture");
        attributes.put("userPassword;binary", "non-secret-test-fixture");
        attributes.put("userPasswordHistory", "kept because only the name prefix matches");

        Attributes result = service.removeExcludedAttributes(attributes, Arrays.asList("unicodepwd", null, "userPassword"));

        assertSame(attributes, result);
        assertEquals(Set.of("cn", "userPasswordHistory"), new AttributesConvertibleValues(attributes).names());
    }

    @Test
    void anOverrideReadingThroughTheLegacyEnumerationMethodsReceivesFilteredResults() throws NamingException {
        Attributes attributes = new BasicAttributes(true);
        attributes.put("cn", "Bernhard Riemann");
        attributes.put("userPassword", "non-secret-test-fixture");
        StubNamingEnumeration results = new StubNamingEnumeration(List.of(new SearchResult("uid=riemann", null, attributes)), null);
        DefaultLdapSearchService legacyOverride = new DefaultLdapSearchService() {
            @Override
            protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> enumeration) throws NamingException {
                List<LdapSearchResult> converted = new ArrayList<>();
                while (enumeration.hasMoreElements()) {
                    SearchResult result = enumeration.nextElement();
                    converted.add(new LdapSearchResult(result.getAttributes(), result.getName()));
                }
                enumeration.close();
                return converted;
            }
        };

        List<LdapSearchResult> converted = legacyOverride.createResults(results, List.of("userPassword"));

        assertEquals(1, converted.size());
        assertEquals(Set.of("cn"), converted.getFirst().getAttributes().names());
        assertTrue(results.closed, "closing the filtered enumeration must close the LDAP enumeration");
    }

    @Test
    void aNamingExceptionFromTheLegacyEnumerationMethodIsReportedWithItsCause() {
        NamingException failure = new NamingException("simulated connection loss");
        StubNamingEnumeration results = new StubNamingEnumeration(List.of(), failure);
        DefaultLdapSearchService legacyOverride = new DefaultLdapSearchService() {
            @Override
            protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> enumeration) {
                enumeration.nextElement();
                return List.of();
            }
        };

        NoSuchElementException thrown = assertThrows(NoSuchElementException.class,
            () -> legacyOverride.createResults(results, List.of("userPassword")));

        assertSame(failure, assertInstanceOf(NamingException.class, thrown.getCause()));
    }

    private static final class StubNamingEnumeration implements NamingEnumeration<SearchResult> {

        private final Iterator<SearchResult> iterator;
        private final NamingException failure;
        private boolean closed;

        private StubNamingEnumeration(List<SearchResult> results, NamingException failure) {
            this.iterator = results.iterator();
            this.failure = failure;
        }

        @Override
        public SearchResult next() throws NamingException {
            if (failure != null) {
                throw failure;
            }
            return iterator.next();
        }

        @Override
        public boolean hasMore() {
            return iterator.hasNext();
        }

        @Override
        public void close() {
            closed = true;
        }

        @Override
        public boolean hasMoreElements() {
            return iterator.hasNext();
        }

        @Override
        public SearchResult nextElement() {
            return iterator.next();
        }
    }
}
