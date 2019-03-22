package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification

class OauthConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OauthConfiguration is disabled if client-secret is present but not enabled"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.client-secret': 'YYYY',
        ], Environment.TEST)

        when:
        context.getBean(OauthConfiguration)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }

    void "OauthConfiguration is present if enabled is set"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(OauthConfiguration)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }

    void "OauthConfiguration is disabled by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(OauthConfiguration)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }
}
