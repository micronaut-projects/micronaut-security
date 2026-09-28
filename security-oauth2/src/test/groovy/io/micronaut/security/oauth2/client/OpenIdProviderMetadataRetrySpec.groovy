package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.context.BeanProvider
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.util.concurrent.atomic.AtomicInteger

class OpenIdProviderMetadataRetrySpec extends Specification {

    void "a transient discovery failure at startup does not permanently disable the OpenID provider"() {
        given: 'an authorization server whose discovery endpoint fails for the first two requests'
        int authServerPort = SocketUtils.findAvailableTcpPort()
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.server.port': authServerPort,
                'spec.name'            : 'AuthServerOpenIdProviderMetadataRetrySpec',
        ])
        FlakyOpenIdConfigurationController controller = authServer.applicationContext.getBean(FlakyOpenIdConfigurationController)
        controller.failures = 2
        HttpClient httpClient = null
        EmbeddedServer server = null

        when: 'the application starts while the discovery endpoint is failing'
        server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                           : 'OpenIdProviderMetadataRetrySpec',
                'micronaut.security.authentication'                   : 'cookie',
                'micronaut.security.oauth2.clients.okta.client-id'    : 'xxx',
                'micronaut.security.oauth2.clients.okta.client-secret': 'yyy',
                'micronaut.security.oauth2.clients.okta.openid.issuer': "http://localhost:${authServerPort}/oauth2/default",
        ])
        httpClient = server.applicationContext.createBean(HttpClient, server.URL, new DefaultHttpClientConfiguration(followRedirects: false))
        BlockingHttpClient client = httpClient.toBlocking()

        then: 'the application started and the discovery endpoint was contacted once'
        server.running
        controller.invocations.get() == 1
        server.applicationContext.containsBean(OpenIdClient, Qualifiers.byName('okta'))

        when: 'login is attempted within the back-off window'
        client.exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'the request fails in a controlled way without contacting the provider again'
        HttpClientResponseException firstFailure = thrown()
        firstFailure.status == HttpStatus.INTERNAL_SERVER_ERROR
        controller.invocations.get() == 1

        when: 'login is attempted after the back-off, while the provider is still failing'
        sleep(backoffMillis())
        client.exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'the fetch is retried and the request fails again in a controlled way'
        HttpClientResponseException secondFailure = thrown()
        secondFailure.status == HttpStatus.INTERNAL_SERVER_ERROR
        controller.invocations.get() == 2

        when: 'the provider has recovered and the back-off elapsed'
        sleep(backoffMillis())
        HttpResponse<?> response = client.exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'login redirects to the provider without restarting the application'
        response.status == HttpStatus.FOUND
        response.header(HttpHeaders.LOCATION).startsWith("http://localhost:${authServerPort}/oauth2/default/v1/authorize")
        controller.invocations.get() == 3

        when: 'login is attempted again'
        response = client.exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'the metadata is memoized'
        response.status == HttpStatus.FOUND
        controller.invocations.get() == 3

        cleanup:
        httpClient?.close()
        server?.close()
        authServer.close()
    }

    void "metadata requested from a non-blocking thread is fetched in the background"() {
        given: 'an authorization server whose discovery endpoint fails for the first request'
        int authServerPort = SocketUtils.findAvailableTcpPort()
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.server.port': authServerPort,
                'spec.name'            : 'AuthServerOpenIdProviderMetadataRetrySpec',
        ])
        FlakyOpenIdConfigurationController controller = authServer.applicationContext.getBean(FlakyOpenIdConfigurationController)
        controller.failures = 1
        String issuer = "http://localhost:${authServerPort}/oauth2/default"
        HttpClient httpClient = null
        EmbeddedServer server = null

        when: 'the application starts while the discovery endpoint is failing'
        server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                           : 'OpenIdProviderMetadataRetrySpec',
                'micronaut.security.authentication'                   : 'cookie',
                'micronaut.security.oauth2.clients.okta.client-id'    : 'xxx',
                'micronaut.security.oauth2.clients.okta.client-secret': 'yyy',
                'micronaut.security.oauth2.clients.okta.openid.issuer': issuer,
        ])
        httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        then:
        controller.invocations.get() == 1

        when: 'the metadata is requested from an event-loop thread after the back-off'
        sleep(backoffMillis())
        client.retrieve(HttpRequest.GET('/metadata/issuer'))

        then: 'the request fails fast'
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.INTERNAL_SERVER_ERROR

        and: 'the metadata is fetched in the background and available to subsequent requests'
        new PollingConditions(timeout: 10).eventually {
            assert controller.invocations.get() == 2
            assert client.retrieve(HttpRequest.GET('/metadata/issuer')) == issuer
        }

        cleanup:
        httpClient?.close()
        server?.close()
        authServer.close()
    }

    private static long backoffMillis() {
        DefaultOpenIdProviderMetadataFetcher.RETRY_BACKOFF.toMillis() + 500
    }

    @Requires(property = 'spec.name', value = 'OpenIdProviderMetadataRetrySpec')
    @Controller('/metadata')
    static class MetadataController {
        private final BeanProvider<DefaultOpenIdProviderMetadata> metadata

        MetadataController(BeanProvider<DefaultOpenIdProviderMetadata> metadata) {
            this.metadata = metadata
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get('/issuer')
        String issuer() {
            metadata.get().issuer
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdProviderMetadataRetrySpec')
    @Controller('/oauth2/default')
    static class FlakyOpenIdConfigurationController {
        final AtomicInteger invocations = new AtomicInteger()
        volatile int failures = 0
        private final String issuer

        FlakyOpenIdConfigurationController(@Property(name = 'micronaut.server.port') int port) {
            this.issuer = "http://localhost:${port}/oauth2/default"
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get('/.well-known/openid-configuration')
        HttpResponse<String> index() {
            if (invocations.incrementAndGet() <= failures) {
                return HttpResponse.status(HttpStatus.SERVICE_UNAVAILABLE)
            }
            HttpResponse.ok('{"issuer":"' + issuer + '","authorization_endpoint":"' + issuer + '/v1/authorize","token_endpoint":"' + issuer + '/v1/token","jwks_uri":"' + issuer + '/v1/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}')
        }
    }
}
