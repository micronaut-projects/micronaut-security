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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.util.*

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "CustomPrincipalConverterTest")
@MicronautTest(transactional = false)
class CustomPrincipalConverterTest {

    @Inject
    private var bookRepository: BookRepository? = null

    @Test
    fun testCreatedByUpdatedByPopulatedOnSave() {
        var book = Book(null, "Tropic of Cancer", "Henry Miller", null, null)
        Assertions.assertNotNull(book.id)
        Assertions.assertEquals("my_unique_identifier", book.creator)
        Assertions.assertEquals("my_unique_identifier", book.editor)
    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
    @Replaces(
        DefaultSecurityService::class
    )
    @Singleton
    class MockSecurityService : SecurityService {
        override fun username(): Optional<String> {
            return Optional.of("sherlock")
        }

        override fun getAuthentication(): Optional<Authentication> {
            val attrs: MutableMap<String, Any> = HashMap()
            attrs["CUSTOM_ID_ATTR"] = "my_unique_identifier"
            return Optional.of(Authentication.build(username().orElseThrow(), attrs))
        }

        override fun isAuthenticated(): Boolean {
            return true
        }

        override fun hasRole(role: String): Boolean {
            return false
        }
    }

    @Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
    @JdbcRepository(dialect = Dialect.H2)
    internal interface BookRepository : CrudRepository<Book?, Long?>
}
