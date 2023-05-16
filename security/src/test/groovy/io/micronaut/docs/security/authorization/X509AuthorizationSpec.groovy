package io.micronaut.docs.security.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.netty.handler.ssl.util.SelfSignedCertificate
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.Certificate

class X509AuthorizationSpec extends Specification {

    void "test custom X509 authentication fetcher"() {
        given:
        Path keyStorePath = Files.createTempFile("micronaut-test-key-store", "pkcs12")
        Path trustStorePath = Files.createTempFile("micronaut-test-trust-store", "jks")

        def certificate = new SelfSignedCertificate()

        KeyStore ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("key", certificate.key(), "".toCharArray(), new Certificate[]{certificate.cert()})
        try (OutputStream os = Files.newOutputStream(keyStorePath)) {
            ks.store(os, "".toCharArray())
        }

        KeyStore ts = KeyStore.getInstance("JKS")
        ts.load(null, null)
        ts.setCertificateEntry("cert", certificate.cert())
        try (OutputStream os = Files.newOutputStream(trustStorePath)) {
            ts.store(os, "123456".toCharArray())
        }

        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': X509AuthorizationSpec.simpleName,
                'micronaut.ssl.enabled': true,
                'micronaut.server.ssl.port': -1,
                'micronaut.server.ssl.build-self-signed': false,
                'micronaut.ssl.client-authentication': "need",
                'micronaut.ssl.key-store.path': 'file://' + keyStorePath.toString(),
                'micronaut.ssl.key-store.type': 'PKCS12',
                'micronaut.ssl.key-store.password': '',
                'micronaut.ssl.trust-store.path': 'file://' + trustStorePath.toString(),
                'micronaut.ssl.trust-store.type': 'JKS',
                'micronaut.ssl.trust-store.password': '123456'])

        when:
        HttpClient client = server.applicationContext.createBean(HttpClient, server.getURL());

        then:
        client.toBlocking().retrieve("/x509") == "CN=localhost"

        cleanup:
        Files.deleteIfExists(keyStorePath)
        Files.deleteIfExists(trustStorePath)
    }

    @Requires(property = "spec.name", value = "X509AuthorizationSpec")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/x509")
    static class MyController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }

}
