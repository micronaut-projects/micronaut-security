package io.micronaut.security.audit.docs.customconverter;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;
import io.micronaut.security.audit.docs.createdby.Book;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.utils.DefaultSecurityService;
import io.micronaut.security.utils.SecurityService;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "CustomPrincipalConverterTest")
@MicronautTest(transactional = false)
public class CustomPrincipalConverterTest {

    @Inject
    private BookRepository bookRepository;

    @Test
    void testCreatedByUpdatedByPopulatedOnSave() {
        Book book = new Book();
        book.setTitle("Tropic of Cancer");
        book.setAuthor("Henry Miller");

        book = bookRepository.save(book);

        Assertions.assertNotNull(book.getId());
        Assertions.assertEquals("my_unique_identifier", book.getCreator());
        Assertions.assertEquals("my_unique_identifier", book.getEditor());
    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
    @Replaces(DefaultSecurityService.class)
    @Singleton
    public static class MockSecurityService implements SecurityService {
        @Override
        public Optional<String> username() {
            return Optional.of("sherlock");
        }

        @Override
        public Optional<Authentication> getAuthentication() {
            Map<String, Object> attrs = new HashMap<>();
            attrs.put("CUSTOM_ID_ATTR", "my_unique_identifier");
            return Optional.of(Authentication.build(username().orElseThrow(), attrs));
        }

        @Override
        public boolean isAuthenticated() {
            return true;
        }

        @Override
        public boolean hasRole(String role) {
            return false;
        }

    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
    @JdbcRepository(dialect = Dialect.H2)
    interface BookRepository extends CrudRepository<Book, Long> {
    }
}
