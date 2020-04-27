package io.micronaut.security.token.propagation

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.endpoints.LoginController
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import spock.lang.AutoCleanup
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise

import java.time.Duration

@Ignore
class TokenPropagationSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "test token propagation"() {
        Map inventoryConfig = [
                'micronaut.application.name': 'inventory',
                (SPEC_NAME_PROPERTY)                          : 'tokenpropagation.inventory',
                'micronaut.security.token.jwt.signatures.secret.validation.secret': 'pleaseChangeThisSecretForANewOne',
        ]

        EmbeddedServer inventoryEmbeddedServer = ApplicationContext.run(EmbeddedServer, inventoryConfig, Environment.TEST)

        Map booksConfig = [
                'micronaut.application.name': 'books',
                (SPEC_NAME_PROPERTY)                          : 'tokenpropagation.books',
                'micronaut.security.token.jwt.signatures.secret.validation.secret': 'pleaseChangeThisSecretForANewOne',
        ]

        EmbeddedServer booksEmbeddedServer = ApplicationContext.run(EmbeddedServer, booksConfig, Environment.TEST)

        given:
        Map gatewayConfig = [
                (SPEC_NAME_PROPERTY): 'tokenpropagation.gateway',
                'micronaut.application.name': 'gateway',
                'micronaut.http.services.books.url': "${booksEmbeddedServer.getURL().toString()}",
                'micronaut.http.services.inventory.url': "${inventoryEmbeddedServer.getURL().toString()}",
                'micronaut.security.endpoints.login.enabled': true,
                'micronaut.security.token.propagation.enabled': true,
                'micronaut.security.token.propagation.service-id-regex': 'books|inventory',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.token.writer.header.enabled': true,
        ]

        EmbeddedServer gatewayEmbeddedServer = ApplicationContext.run(EmbeddedServer, gatewayConfig, Environment.TEST)

        def configuration = new DefaultHttpClientConfiguration()
        configuration.setReadTimeout(Duration.ofSeconds(30))
        RxHttpClient gatewayClient = gatewayEmbeddedServer.applicationContext.createBean(RxHttpClient, gatewayEmbeddedServer.getURL(), configuration)

        when: 'attempt to login'
        def creds = new UsernamePasswordCredentials('sherlock', 'elementary')
        HttpResponse rsp = gatewayClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then: 'login works'
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        rsp.body().refreshToken

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
    }
}
