package io.micronaut.security.audit

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.core.convert.ConversionContext
import io.micronaut.core.convert.TypeConverter
import io.micronaut.data.jdbc.annotation.JdbcRepository
import io.micronaut.data.model.query.builder.sql.Dialect
import io.micronaut.data.repository.CrudRepository
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Put
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.converters.PrincipalToStringConverter
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
@Property(name = "spec.name", value = "AuditingCustomIdentitySpec")
@MicronautTest(transactional = false)
class AuditingCustomIdentitySpec extends Specification {

    @Inject
    MessageRepository messageRepository

    @Inject
    @Client("/")
    HttpClient httpClient

    void "createdBy and updatedBy are populated automatically with a custom converter"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.POST("/messages", [title: 'FooBar']), Message.class)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count()) + 1
        message.title == "FooBar"
        message.creator == "SHERLOCK"
        message.lastModifiedBy == "SHERLOCK"

        when:
        message.title = "FooBaz"
        Message updatedMessage = client.retrieve(HttpRequest.PUT("/messages", message), Message.class)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count())
        updatedMessage.title == "FooBaz"
        updatedMessage.creator == "SHERLOCK"
        updatedMessage.lastModifiedBy == "WATSON"
    }

    void "updatedBy is still auto populated on update with a custom converter if createdBy is null"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.POST("/messages/unsecured", [title: 'FooBar']), Message.class)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count()) + 1
        message.title == "FooBar"
        !message.creator
        !message.lastModifiedBy

        when:
        message.title = "FooBaz"
        Message updatedMessage = client.retrieve(HttpRequest.PUT("/messages", message), Message.class)

        then:
        noExceptionThrown()
        messageRepository.count() == old(messageRepository.count())
        updatedMessage.title == "FooBaz"
        !updatedMessage.creator
        updatedMessage.lastModifiedBy == "WATSON"
    }

    @Requires(property = "spec.name", value = "AuditingCustomIdentitySpec")
    @Singleton
    static class CustomPrincipalToStringConverter implements TypeConverter<Principal, String> {
        @Override
        Optional<String> convert(Principal principal, Class<String> targetType, ConversionContext context) {
            Optional.ofNullable(principal.getName()).map(identity -> identity.toUpperCase())
        }
    }

    @Requires(property = "spec.name", value = "AuditingCustomIdentitySpec")
    @Controller("/messages")
    static class MessageController {
        private final MessageRepository messageRepository

        MessageController(MessageRepository messageRepository) {
            this.messageRepository = messageRepository
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Post
        Message save(@Body Message body) {
            messageRepository.save(body)
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Put
        Message update(@Body Message body) {
            messageRepository.update(body)
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Post("/unsecured")
        Message saveUnsecured(@Body Message body) {
            messageRepository.save(body)
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Put("/unsecured")
        Message updateUnsecured(@Body Message body) {
            messageRepository.update(body)
        }
    }

    @Requires(property = "spec.name", value = "AuditingCustomIdentitySpec")
    @Singleton
    static class FooAuthenticationFetcher implements AuthenticationFetcher<HttpRequest> {

        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest request) {
            if (request.uri.toString().endsWith("/unsecured")) {
                return Publishers.empty()
            }

            if (request.method == HttpMethod.POST) {
                return Publishers.just(Authentication.build("sherlock"))
            } else if (request.method == HttpMethod.PUT) {
                return Publishers.just(Authentication.build("watson"))
            }

            return Publishers.empty()
        }
    }

    @Requires(property = "spec.name", value = "AuditingCustomIdentitySpec")
    @JdbcRepository(dialect = Dialect.H2)
    static interface MessageRepository extends CrudRepository<Message, Long> {
    }
}
