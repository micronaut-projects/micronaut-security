import java
from jakarta.inject import Singleton
from java.util import Optional
from micronaut.context import ApplicationContext
from micronaut.context.annotation import Replaces, Requires
from micronaut.data.jdbc.annotation import JdbcRepository
from micronaut.data.repository import CrudRepository
from micronaut.security.audit.docs.createdby.Book import Book
from micronaut.security.authentication import Authentication
from micronaut.security.utils import DefaultSecurityService, SecurityService
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


# A Python TypeConverter bean is instantiated by the application context before the GraalPy runtime
# of that context exists, so the converter is exercised in a context started from the test's own
# (already initialised) Python runtime.
@MicronautTest
class CustomPrincipalConverterTest:

    @Test
    def test_created_by_updated_by_populated_on_save(self):
        ctx = ApplicationContext.run({
            "datasources.default.dialect": "H2",
            "datasources.default.schema-generate": "CREATE_DROP",
            "datasources.default.url": "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE",
            "datasources.default.username": "sa",
            "datasources.default.driver-class-name": "org.h2.Driver",
            "spec.name": "CustomPrincipalConverterTest",
        })
        try:
            # TODO(python): java.type needed because the Python repository class is the runtime type argument of
            # ApplicationContext.getBean(); the Python class object itself is not accepted as a Java Class
            BookRepositoryClass = java.type("micronaut.security.audit.docs.customconverter.BookRepository")
            bookRepository = ctx.getBean(BookRepositoryClass)
            book = Book(None, "Tropic of Cancer", "Henry Miller", None, None)

            book = bookRepository.save(book)

            assert book.id is not None
            assert book.creator == "my_unique_identifier"
            assert book.editor == "my_unique_identifier"
        finally:
            ctx.close()


@Requires(property="spec.name", value="CustomPrincipalConverterTest")
@Replaces(DefaultSecurityService)
@Singleton
class MockSecurityService(SecurityService):

    def username(self) -> Optional[str]:
        return Optional.of("sherlock")

    def getAuthentication(self) -> Optional[Authentication]:
        attrs = {"CUSTOM_ID_ATTR": "my_unique_identifier"}
        return Optional.of(Authentication.build(self.username().orElseThrow(), attrs))

    def isAuthenticated(self) -> bool:
        return True

    def hasRole(self, role: str) -> bool:
        return False


@Requires(property="spec.name", value="CustomPrincipalConverterTest")
@JdbcRepository(dialect="H2")
class BookRepository(CrudRepository[Book, int]):
    ...
