package io.micronaut.security.docs.fetchmetadata

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = 'spec.name', value = 'PublicResourceFetchMetadataRuleSpec')
@MicronautTest
class PublicResourceFetchMetadataRuleSpec extends Specification {

    @Inject
    @Client('/')
    HttpClient httpClient

    void 'cross-site subresource requests reach the public resource'() {
        expect:
        httpClient.toBlocking().exchange(crossSiteImage('/favicon.ico'), String).status == HttpStatus.OK
    }

    void 'cross-site subresource requests to other resources are rejected'() {
        when:
        httpClient.toBlocking().exchange(crossSiteImage('/account'), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN
    }

    private static HttpRequest<?> crossSiteImage(String path) {
        HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, 'cross-site')
            .header(HttpHeaders.SEC_FETCH_MODE, 'no-cors')
            .header(HttpHeaders.SEC_FETCH_DEST, 'image')
    }

    @Requires(property = 'spec.name', value = 'PublicResourceFetchMetadataRuleSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class PublicResourceController {

        @Get(uri = '/favicon.ico', produces = MediaType.TEXT_PLAIN)
        String favicon() {
            'icon'
        }

        @Get(uri = '/account', produces = MediaType.TEXT_PLAIN)
        String account() {
            'account'
        }
    }
}
