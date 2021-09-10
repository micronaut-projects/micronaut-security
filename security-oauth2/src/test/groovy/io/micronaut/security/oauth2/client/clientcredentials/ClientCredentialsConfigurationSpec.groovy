package io.micronaut.security.oauth2.client.clientcredentials

import io.micronaut.context.ApplicationContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.time.Duration

class ClientCredentialsConfigurationSpec extends Specification {

    void "advanced expiration defaults to 30 seconds"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.clients.authservermanual.token.url': "http://foo.bar/token",
                'micronaut.security.oauth2.clients.authservermanual.client-id': 'XXX',
                'micronaut.security.oauth2.clients.authservermanual.client-secret': 'YYY',
                'micronaut.security.oauth2.clients.authservermanual.client-credentials.scope': 'create-file' // you have to specify a property of client-credentials for client credentials configuration to be created.
        ])

        when:
        OauthClientConfiguration configuration = applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual"))

        then:
        noExceptionThrown()

        expect:
        configuration.getClientCredentials().get().advancedExpiration == Duration.ofSeconds(30)

        cleanup:
        applicationContext.close()
    }

    void "it is possinble to set advancedExpiration with client-credentials.advanced-expiration"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.clients.authservermanual.token.url': "http://foo.bar/token",
                'micronaut.security.oauth2.clients.authservermanual.client-id': 'XXX',
                'micronaut.security.oauth2.clients.authservermanual.client-secret': 'YYY',
                'micronaut.security.oauth2.clients.authservermanual.client-credentials.advanced-expiration': '0s',
        ])

        when:
        OauthClientConfiguration configuration = applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual"))

        then:
        noExceptionThrown()

        expect:
        configuration.getClientCredentials().get().advancedExpiration == Duration.ofSeconds(0)

        cleanup:
        applicationContext.close()
    }

    void "is is possible to set additionalRequestParams with client-credentials.additional-request-params"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.clients.authservermanual.token.url': "http://foo.bar/token",
                'micronaut.security.oauth2.clients.authservermanual.client-id': 'XXX',
                'micronaut.security.oauth2.clients.authservermanual.client-secret': 'YYY',
                'micronaut.security.oauth2.clients.authservermanual.client-credentials.advanced-expiration': '0s',
                'micronaut.security.oauth2.clients.authservermanual.client-credentials.additional-request-params.audience': 'test',
        ])

        when:
        OauthClientConfiguration configuration = applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual"))

        then:
        noExceptionThrown()

        expect:
        configuration.getClientCredentials().get().getAdditionalRequestParams().get("audience") == "test"

        cleanup:
        applicationContext.close()
    }
}
