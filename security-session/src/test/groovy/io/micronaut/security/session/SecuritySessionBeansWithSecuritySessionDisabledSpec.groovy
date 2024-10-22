package io.micronaut.security.session

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class SecuritySessionBeansWithSecuritySessionDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.session.enabled': false,
        ]
    }

    @Unroll("if micronaut.security.session.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.session.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                SecuritySessionConfigurationProperties,
                SessionAuthenticationFetcher,
                SessionLoginHandler,
                SessionLogoutHandler
        ]

        description = clazz.name
    }
}
