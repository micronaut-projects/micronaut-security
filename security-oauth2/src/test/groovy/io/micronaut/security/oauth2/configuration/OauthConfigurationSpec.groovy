package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification

class OauthConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OauthConfiguration binds id and secret"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
        ], Environment.TEST)

        when:
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration)

        then:
        noExceptionThrown()
        clientConfiguration.getName() == "foo"
        clientConfiguration.getClientId() == "XXXX"
        clientConfiguration.getClientSecret() == "YYYY"

        cleanup:
        context.close()
    }

    void "OauthConfiguration is disabled by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
        ], Environment.TEST)

        when:
        context.getBean(OauthClientConfiguration)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }
}
