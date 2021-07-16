package io.micronaut.docs.security.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification

class X509AuthorizationSpec extends Specification {

    void "test custom X509 authentication fetcher"() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': X509AuthorizationSpec.simpleName,
                'micronaut.ssl.enabled': true,
                'micronaut.ssl.buildSelfSigned': false,
                'micronaut.ssl.clientAuthentication': "need",
                'micronaut.ssl.key-store.path': 'classpath:ssl/KeyStore.p12',
                'micronaut.ssl.key-store.type': 'PKCS12',
                'micronaut.ssl.key-store.password': '',
                'micronaut.ssl.trust-store.path': 'classpath:ssl/TrustStore.jks',
                'micronaut.ssl.trust-store.type': 'JKS',
                'micronaut.ssl.trust-store.password': '123456'])

        when:
        HttpClient client = server.applicationContext.createBean(HttpClient, server.getURL());

        then:
        client.toBlocking().retrieve("/x509") == "O=Test CA,ST=Some-State,C=US"
    }

    @Requires(property = "spec.name", value = "X509AuthorizationSpec")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/x509")
    static class MyController {
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }

}
