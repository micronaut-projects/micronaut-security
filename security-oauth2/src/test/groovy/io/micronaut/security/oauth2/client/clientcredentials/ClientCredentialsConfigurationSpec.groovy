package io.micronaut.security.oauth2.client.clientcredentials

import io.micronaut.context.ApplicationContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class ClientCredentialsConfigurationSpec extends Specification {

    void "advanced expiration defaults to 30 seconds"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.clients.authservermanual.token.url': "http://foo.bar/token",
                'micronaut.security.oauth2.clients.authservermanual.client-id': 'XXX',
                'micronaut.security.oauth2.clients.authservermanual.client-secret': 'YYY',
        ])

        expect:
        applicationContext.containsBean(OauthClientConfiguration, Qualifiers.byName("authservermanual"))
        applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual")).getClientCredentials().isPresent()
        applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual")).getClientCredentials().get().advancedExpiration == 30

        cleanup:
        applicationContext.close()
    }

    void "it is possinble to set advancedExpiration with client-credentials.advanced-expiration"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.oauth2.clients.authservermanual.token.url': "http://foo.bar/token",
                'micronaut.security.oauth2.clients.authservermanual.client-id': 'XXX',
                'micronaut.security.oauth2.clients.authservermanual.client-secret': 'YYY',
                'micronaut.security.oauth2.clients.authservermanual.client-credentials.advanced-expiration': 0,
        ])

        expect:
        applicationContext.containsBean(OauthClientConfiguration, Qualifiers.byName("authservermanual"))
        applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual")).getClientCredentials().isPresent()
        applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName("authservermanual")).getClientCredentials().get().advancedExpiration == 0

        cleanup:
        applicationContext.close()
    }
}
