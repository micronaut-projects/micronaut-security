package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.ConfigurationFixture
import io.micronaut.security.oauth2.client.DefaultOpenIdClient
import spock.lang.Specification

class OpenIdClientConditionSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OpenIdClientCondition evaluates to true for openid client with manual token and authorization urls"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.foo.openid.authorization.url': 'https://appleid.apple.com/auth/authorize',
                'micronaut.security.oauth2.clients.foo.openid.token.url': 'https://appleid.apple.com/auth/token'
        ], Environment.TEST)

        when:
        context.getBean(DefaultOpenIdClient)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }
}
