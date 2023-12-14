package io.micronaut.security.audit.docs.createdby;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.utils.DefaultSecurityService;
import io.micronaut.security.utils.SecurityService;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "UserAuditingTest")
@MicronautTest(transactional = false)
public class UserAuditingTest {

    @Inject
    BookRepository bookRepository;

    @Test
    void testCreatedByUpdatedByPopulatedOnSave() {
        Book book = new Book();
        book.setTitle("Tropic of Cancer");
        book.setAuthor("Henry Miller");

        book = bookRepository.save(book);

        Assertions.assertNotNull(book.getId());
        Assertions.assertEquals("sherlock", book.getCreator());
        Assertions.assertEquals("sherlock", book.getEditor());
    }

    @Requires(property = "spec.name", value = "UserAuditingTest")
    @Replaces(DefaultSecurityService.class)
    @Singleton
    static class MockSecurityService implements SecurityService {

        @Override
        public Optional<String> username() {
            return Optional.of("sherlock");
        }

        @Override
        public Optional<Authentication> getAuthentication() {
            return Optional.of(Authentication.build(username().orElseThrow()));
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

    @Requires(property = "spec.name", value = "UserAuditingTest")
    @JdbcRepository(dialect = Dialect.H2)
    interface BookRepository extends CrudRepository<Book, Long> {
    }

}
