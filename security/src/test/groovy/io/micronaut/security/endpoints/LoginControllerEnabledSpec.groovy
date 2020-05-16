package io.micronaut.security.endpoints

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.ApplicationContextSpecification
import spock.lang.Unroll

class LoginControllerEnabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.login.enabled': false,

        ]
    }

    @Unroll("if micronaut.security.endpoints.login.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.endpoints.login.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                LoginController,
                LoginControllerConfigurationProperties,
        ]

        description = clazz.name
    }

}
