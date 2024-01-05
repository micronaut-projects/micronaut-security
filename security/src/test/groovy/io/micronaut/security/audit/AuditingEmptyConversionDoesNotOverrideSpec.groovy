package io.micronaut.security.audit

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.core.convert.ConversionContext
import io.micronaut.core.convert.TypeConverter
import io.micronaut.data.annotation.Query
import io.micronaut.data.jdbc.annotation.JdbcRepository
import io.micronaut.data.model.query.builder.sql.Dialect
import io.micronaut.data.repository.CrudRepository
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Put
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.AuthenticationFetcher
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import spock.lang.Specification

import java.security.Principal

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "AuditingFailingConverterSpec")
@MicronautTest(transactional = false)
class AuditingEmptyConversionDoesNotOverrideSpec extends Specification {
    @Inject
    MessageRepository messageRepository

    @Inject
    @Client("/")
    HttpClient httpClient

    void "empty conversion does not override fields annotated with @CreatedBy or @UpdatedBy"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = messageRepository.save(new Message(id: null, title:  "FooBar", creator: "moriarty", lastModifiedBy: "moriarty"))

        then:
        message.creator == "moriarty"
        message.lastModifiedBy == "moriarty"

        Message updatedMessage = client.retrieve(HttpRequest.PUT("/messages", new Message(id: message.id, title: "FooBaz")), Message.class)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count())
        updatedMessage.title == "FooBaz"
        updatedMessage.creator == "moriarty"
        updatedMessage.lastModifiedBy == "moriarty"
    }

    @Requires(property = "spec.name", value = "AuditingFailingConverterSpec")
    @Singleton
    static class CustomPrincipalToStringConverter implements TypeConverter<Principal, String> {
        @Override
        Optional<String> convert(Principal principal, Class<String> targetType, ConversionContext context) {
            Optional.empty()
        }
    }

    @Requires(property = "spec.name", value = "AuditingFailingConverterSpec")
    @Controller("/messages")
    static class MessageController {
        private final MessageRepository messageRepository

        MessageController(MessageRepository messageRepository) {
            this.messageRepository = messageRepository
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Put
        Message update(@Body Message body) {
            if (body.id == null) {
                return messageRepository.update(body)
            } else {
                messageRepository.update(body.id, body.title)
                return messageRepository.findById(body.id).orElse(null)
            }
        }

    }

    @Requires(property = "spec.name", value = "AuditingFailingConverterSpec")
    @Singleton
    static class FooAuthenticationFetcher implements AuthenticationFetcher<HttpRequest> {
        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest request) {
            if (request.method == HttpMethod.PUT) {
                return Publishers.just(Authentication.build("sherlock"))
            }

            return Publishers.empty()
        }
    }

    @Requires(property = "spec.name", value = "AuditingFailingConverterSpec")
    @JdbcRepository(dialect = Dialect.H2)
    static interface MessageRepository extends CrudRepository<Message, Long> {

        @Query("UPDATE message SET title = :title WHERE id = :id")
        void update(Long id, String title)
    }
}
