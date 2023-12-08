package io.micronaut.security.createdby

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.data.annotation.event.PrePersist
import io.micronaut.data.event.listeners.PrePersistEventListener
import io.micronaut.data.jdbc.annotation.JdbcRepository
import io.micronaut.data.model.query.builder.sql.Dialect
import io.micronaut.data.repository.CrudRepository
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.AuthenticationFetcher
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.utils.SecurityService
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import spock.lang.Specification

@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "datasources.default.url", value = "jdbc:h2:mem:devDb;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "spec.name", value = "CreatedBySpec")
@MicronautTest(transactional = false)
class CreatedBySpec extends Specification {
    @Inject
    MessageRepository messageRepository

    @Inject
    @Client("/")
    HttpClient httpClient

    void "createdBy is populated automatically"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        "sherlock" == client.retrieve(HttpRequest.POST("/messages", [title: 'FooBar']).accept(MediaType.TEXT_PLAIN))

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count()) + 1
    }

    @Requires(property = "spec.name", value = "CreatedBySpec")
    @Singleton
    static class CreatedByListenerListener implements PrePersistEventListener<Message>  {
        private final SecurityService securityService

        CreatedByListenerListener(SecurityService securityService) {
            this.securityService = securityService
        }

        @Override
        boolean prePersist(@NonNull Message entity) {
            entity.createdBy = securityService.username()
        }
    }

    @Requires(property = "spec.name", value = "CreatedBySpec")
    @Controller("/messages")
    static class MessageController {
        private final MessageRepository messageRepository

        MessageController(MessageRepository messageRepository) {
            this.messageRepository = messageRepository
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Post
        @Produces(MediaType.TEXT_PLAIN)
        String save(@Body Map<String, Object> body) {
            messageRepository.save(new Message(title: body.get("title"))).createdBy
        }
    }

    @Requires(property = "spec.name", value = "CreatedBySpec")
    @Singleton
    static class FooAuthenticationFetcher implements AuthenticationFetcher<HttpRequest> {

        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest request) {
            Publishers.just(Authentication.build("sherlock"))
        }
    }

    @Requires(property = "spec.name", value = "CreatedBySpec")
    @JdbcRepository(dialect = Dialect.H2)
    static interface MessageRepository extends CrudRepository<Message, Long> {
    }
}
