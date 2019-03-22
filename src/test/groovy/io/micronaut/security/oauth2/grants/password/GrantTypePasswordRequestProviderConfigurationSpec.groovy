package io.micronaut.security.oauth2.grants.password

import io.micronaut.context.ApplicationContext
import io.micronaut.http.MediaType
import spock.lang.Shared
import spock.lang.Specification

class GrantTypePasswordRequestProviderConfigurationSpec extends Specification {

    @Shared
    Map<String, Object> conf = [
            'micronaut.security.enabled': true,
            'micronaut.security.token.jwt.enabled': true,
            'micronaut.security.oauth2.enabled': true,
            'micronaut.security.oauth2.client-secret': 'YYYYY',
    ] as Map<String, Object>

    def "Password grant type default scopes is openid"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(conf)

        when:
        GrantTypePasswordRequestProviderConfiguration configuration = applicationContext.getBean(GrantTypePasswordRequestProviderConfiguration)

        then:
        noExceptionThrown()
        configuration.getScopes() == ['openid']

        cleanup:
        applicationContext.close()
    }

    def "Password grant type default enabled is false"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(conf)

        when:
        GrantTypePasswordRequestProviderConfiguration configuration = applicationContext.getBean(GrantTypePasswordRequestProviderConfiguration)

        then:
        noExceptionThrown()
        !configuration.isEnabled()

        cleanup:
        applicationContext.close()
    }

    def "Password grant type default content type is application/x-www-form-urlencoded"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(conf)

        when:
        GrantTypePasswordRequestProviderConfiguration configuration = applicationContext.getBean(GrantTypePasswordRequestProviderConfiguration)

        then:
        noExceptionThrown()
        configuration.getContentType() == MediaType.APPLICATION_FORM_URLENCODED_TYPE

        cleanup:
        applicationContext.close()
    }
}
