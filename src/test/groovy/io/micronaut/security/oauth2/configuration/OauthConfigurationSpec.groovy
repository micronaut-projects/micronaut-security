package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification

class OauthConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OauthConfiguration is disabled if client-secret is present but no client-id"() {
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

    void "OauthConfiguration is enabled if client-id is present"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.client-id': 'YYYY',
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


    void "OauthConfiguration is enabled via application-xxx.yml file"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
        ], Environment.TEST, "xxx")

        when:
        OauthConfiguration oauthConfiguration = context.getBean(OauthConfiguration)

        then:
        oauthConfiguration.clientId == "XXXXX"

        cleanup:
        context.close()
    }

    void "OauthConfiguration can be disabled after enabling it via application-xxx.yml file"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                "micronaut.security.oauth2.enabled": false,
        ], Environment.TEST, "xxx")

        when:
        context.getBean(OauthConfiguration)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }
}
