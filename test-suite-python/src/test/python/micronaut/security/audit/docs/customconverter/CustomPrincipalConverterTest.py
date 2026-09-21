from typing import Annotated

from jakarta.inject import Inject, Singleton
from java.util import Optional
from micronaut.context.annotation import Property, Replaces, Requires
from micronaut.data.jdbc.annotation import JdbcRepository
from micronaut.data.repository import CrudRepository
from micronaut.security.audit.docs.createdby.Book import Book
from micronaut.security.authentication import Authentication
from micronaut.security.utils import DefaultSecurityService, SecurityService
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="datasources.default.dialect", value="H2")
@Property(name="datasources.default.schema-generate", value="CREATE_DROP")
@Property(name="datasources.default.url", value="jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name="datasources.default.username", value="sa")
@Property(name="datasources.default.driver-class-name", value="org.h2.Driver")
@Property(name="spec.name", value="CustomPrincipalConverterTest")
@MicronautTest(transactional=False)
class CustomPrincipalConverterTest:
    bookRepository: Annotated["BookRepository", Inject]

    @Test
    def test_created_by_updated_by_populated_on_save(self):
        book = Book(None, "Tropic of Cancer", "Henry Miller", None, None)

        book = self.bookRepository.save(book)

        assert book.id is not None
        assert book.creator == "my_unique_identifier"
        assert book.editor == "my_unique_identifier"


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
