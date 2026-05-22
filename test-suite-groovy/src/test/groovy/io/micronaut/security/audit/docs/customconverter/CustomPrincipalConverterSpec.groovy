package io.micronaut.security.audit.docs.customconverter

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.data.jdbc.annotation.JdbcRepository
import io.micronaut.data.model.query.builder.sql.Dialect
import io.micronaut.data.repository.CrudRepository
import io.micronaut.security.audit.docs.createdby.Book
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.utils.DefaultSecurityService
import io.micronaut.security.utils.SecurityService
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "CustomPrincipalConverterSpec")
@MicronautTest(transactional = false)
class CustomPrincipalConverterSpec extends Specification {

    @Inject
    BookRepository bookRepository

    def "createdBy and updatedBy are populated on save"() {
        given:
        Book book = new Book()
        book.title = "Tropic of Cancer"
        book.author = "Henry Miller"

        when:
        book = bookRepository.save(book)

        then:
        book.id
        book.creator == "my_unique_identifier"
        book.editor == "my_unique_identifier"
    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterSpec")
    @Replaces(DefaultSecurityService.class)
    @Singleton
    static class MockSecurityService implements SecurityService {

        @Override
        Optional<String> username() {
            Optional.of("sherlock")
        }

        @Override
        Optional<Authentication> getAuthentication() {
            Optional.of(Authentication.build(username().orElseThrow(), [
                    "CUSTOM_ID_ATTR" : "my_unique_identifier"
            ]))
        }

        @Override
        boolean isAuthenticated() {
            return true
        }

        @Override
        boolean hasRole(String role) {
            return false
        }
    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterSpec")
    @JdbcRepository(dialect = Dialect.H2)
    static interface BookRepository extends CrudRepository<Book, Long> {
    }
}
