package io.micronaut.security.audit

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.data.jdbc.annotation.JdbcRepository
import io.micronaut.data.model.query.builder.sql.Dialect
import io.micronaut.data.repository.CrudRepository
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.CreatedBy
import io.micronaut.security.annotation.Secured
import io.micronaut.security.annotation.UpdatedBy
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.AuthenticationFetcher
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import jakarta.validation.constraints.NotBlank
import org.reactivestreams.Publisher
import spock.lang.Specification

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "CreatedByUpdatedByTypeNoConverterSpec")
@MicronautTest(transactional = false)
class CreatedByUpdatedByTypeNoConverterSpec extends Specification {
    @Inject
    MessageRepository messageRepository

    @Inject
    @Client("/")
    HttpClient httpClient

    void "@CreatedBy @UpdatedBy in combination with @Nullable"() {
        given:
        String title = "FooBar"
        BlockingHttpClient client = httpClient.toBlocking()
        HttpRequest request = HttpRequest.POST("/messages/authenticated", new Message(title:  title))

        when:
        client.retrieve(request, Message)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count())
    }

    @Requires(property = "spec.name", value = "CreatedByUpdatedByTypeNoConverterSpec")
    @Controller("/messages")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class MessageController {
        private final MessageRepository messageRepository

        MessageController(MessageRepository messageRepository) {
            this.messageRepository = messageRepository
        }

        @Post("/authenticated")
        Message authenticated(@Body Message body) {
            messageRepository.save(body)
        }
    }

    @Requires(property = "spec.name", value = "CreatedByUpdatedByTypeNoConverterSpec")
    @Singleton
    static class FooAuthenticationFetcher implements AuthenticationFetcher<HttpRequest> {
        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest request) {
            request.path.contains("authenticated")
                    ? Publishers.just(Authentication.build("sherlock"))
                    : Publishers.empty()
        }
    }

    @Requires(property = "spec.name", value = "CreatedByUpdatedByTypeNoConverterSpec")
    @JdbcRepository(dialect = Dialect.H2)
    static interface MessageRepository extends CrudRepository<Message, Long> {
    }

    @MappedEntity("message")
    static class Message {
        @Id
        @GeneratedValue
        @Nullable
        Long id

        @NotBlank
        String title

        @CreatedBy
        @Nullable
        Long creator

        @UpdatedBy
        @Nullable
        Long lastModifiedBy
    }
}
