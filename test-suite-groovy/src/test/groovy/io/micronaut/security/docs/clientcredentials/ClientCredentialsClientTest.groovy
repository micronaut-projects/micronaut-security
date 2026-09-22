package io.micronaut.security.docs.clientcredentials

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Property
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "ClientCredentialsClientTest")
@Property(name = "micronaut.security.oauth2.clients.companyauthserver.client-id", value = "XXX")
@Property(name = "micronaut.security.oauth2.clients.companyauthserver.client-secret", value = "YYY")
@Property(name = "micronaut.security.oauth2.clients.companyauthserver.token.url", value = "https://foo.bar/token")
@Property(name = "micronaut.security.oauth2.clients.companyauthserver.token.auth-method", value = "client_secret_basic")
@Property(name = "micronaut.security.oauth2.clients.google.client-id", value = "ZZZZ")
@Property(name = "micronaut.security.oauth2.clients.google.client-secret", value = "PPPP")
@Property(name = "micronaut.security.oauth2.clients.google.token.url", value = "https://oauth2.googleapis.com/token")
@MicronautTest(startApplication = false)
class ClientCredentialsClientTest extends Specification {

    @Inject
    MyClass myClass

    @Inject
    ApplicationContext beanContext

    void "client credentials clients can be retrieved by name"() {
        expect:
        myClass.googleClientCredentialsClient

        when:
        //tag::getBean[]
        ClientCredentialsClient client = beanContext.getBean(ClientCredentialsClient, Qualifiers.byName("companyauthserver"))
        //end::getBean[]

        then:
        client
    }
}
