package io.micronaut.security.token.propagation

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import spock.lang.Ignore
import spock.lang.Issue
import spock.lang.Specification

import java.time.Duration

class TokenPropagationSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Issue("https://github.com/micronaut-projects/micronaut-core/issues/5625")
    @Ignore // Flaky due to above issue
    void "test token propagation"() {
        Map<String, Object> inventoryConfig = [
                'micronaut.application.name': 'inventory',
                (SPEC_NAME_PROPERTY)                          : 'tokenpropagation.inventory',
                'micronaut.security.token.jwt.signatures.secret.validation.secret': 'pleaseChangeThisSecretForANewOne',
        ]

        EmbeddedServer inventoryEmbeddedServer = ApplicationContext.run(EmbeddedServer, inventoryConfig)

        Map<String, Object> booksConfig = [
                'micronaut.application.name': 'books',
                (SPEC_NAME_PROPERTY)                          : 'tokenpropagation.books',
                'micronaut.security.token.jwt.signatures.secret.validation.secret': 'pleaseChangeThisSecretForANewOne',
        ]

        EmbeddedServer booksEmbeddedServer = ApplicationContext.run(EmbeddedServer, booksConfig)

        given:
        Map<String, Object> gatewayConfig = [
                (SPEC_NAME_PROPERTY): 'tokenpropagation.gateway',
                'micronaut.application.name': 'gateway',
                'micronaut.security.authentication': 'bearer',
                'micronaut.http.services.books.url': "${booksEmbeddedServer.getURL().toString()}",
                'micronaut.http.services.inventory.url': "${inventoryEmbeddedServer.getURL().toString()}",
                'micronaut.security.token.propagation.enabled': true,
                'micronaut.security.token.propagation.service-id-regex': 'books|inventory',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]

        EmbeddedServer gatewayEmbeddedServer = ApplicationContext.run(EmbeddedServer, gatewayConfig)

        def configuration = new DefaultHttpClientConfiguration()
        configuration.setReadTimeout(Duration.ofSeconds(30))
        HttpClient gatewayClient = gatewayEmbeddedServer.applicationContext.createBean(HttpClient, gatewayEmbeddedServer.getURL(), configuration)

        when: 'attempt to login'
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('sherlock', 'elementary')
        HttpResponse rsp = gatewayClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then: 'login works'
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken

        when:

        // tag::bearerAuth[]
        String accessToken = rsp.body().accessToken
        List<Book> books = gatewayClient.toBlocking().retrieve(HttpRequest.GET("/api/gateway")
                .bearerAuth(accessToken), Argument.listOf(Book))
        // end::bearerAuth[]
        then:
        noExceptionThrown()
        books
        books.size() == 2

        cleanup:
        gatewayEmbeddedServer.close()
        booksEmbeddedServer.close()
        inventoryEmbeddedServer.close()
    }

    @Requires(property = "spec.name", value = "tokenpropagation.inventory")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/api")
    static class InventoryController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/inventory/{isbn}")
        HttpResponse<Integer> inventory(String isbn) {
            if (isbn.equals("1491950358")) {
                return HttpResponse.ok(2);
            } else if (isbn.equals("1680502395")) {
                return HttpResponse.ok(3);
            } else {
                return HttpResponse.notFound();
            }
        }
    }

    @Requires(property = "spec.name", value = "tokenpropagation.books")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/api")
    static class BooksController {
        @Get("/books")
        List<Book> list() {
            return Arrays.asList(new Book("1491950358", "Building Microservices"),
                    new Book("1680502395", "Release It!"));
        }
    }

    @Requires(property = "spec.name", value = "tokenpropagation.gateway")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/api")
    static class GatewayController {

        private final BooksClient booksClient;
        private final InventoryClient inventoryClient;

        GatewayController(BooksClient booksClient,
                                 InventoryClient inventoryClient) {
            this.booksClient = booksClient;
            this.inventoryClient = inventoryClient;
        }

        @Get("/gateway")
        Publisher<Book> findAll() {
            return Flux.from(booksClient.fetchBooks())
                    .flatMap({ b ->
                        Mono.from(inventoryClient.inventory(b.getIsbn()))
                                .filter({ stock -> stock > 0 })
                                .map({ stock ->
                                    b.setStock(stock);
                                return b;
                            })
                    })
        }
    }

    @Requires(property = "spec.name", value = "tokenpropagation.gateway")
    @Client("books")
    static interface BooksClient {
        @Get("/api/books")
        Publisher<Book> fetchBooks();
    }

    @Requires(property = "spec.name", value = "tokenpropagation.gateway")
    @Singleton
    static class SampleAuthenticationProvider extends MockAuthenticationProvider {
        SampleAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('sherlock'), new SuccessAuthenticationScenario('watson')])
        }
    }

    @Requires(property = "spec.name", value = "tokenpropagation.gateway")
    @Client("inventory")
    static interface InventoryClient {

        @Consumes(MediaType.TEXT_PLAIN)
        @Get("/api/inventory/{isbn}")
        @SingleResult
        Publisher<Integer> inventory(String isbn);
    }

    static class Book {
        private String isbn;
        private String name;
        private Integer stock;

        Book() {

        }

        Book(String isbn, String name) {
            this.isbn = isbn;
            this.name = name;
        }

        Book(String isbn, String name, Integer stock) {
            this.isbn = isbn;
            this.name = name;
            this.stock = stock;
        }

        String getIsbn() {
            return isbn;
        }

        void setIsbn(String isbn) {
            this.isbn = isbn;
        }

        String getName() {
            return name;
        }

        void setName(String name) {
            this.name = name;
        }

        void setStock(Integer stock) {
            this.stock = stock;
        }

        Integer getStock() {
            return stock;
        }
    }

}
