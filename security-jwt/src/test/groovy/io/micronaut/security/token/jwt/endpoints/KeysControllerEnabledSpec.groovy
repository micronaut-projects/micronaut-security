package io.micronaut.security.token.jwt.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.NoSuchBeanException
import spock.lang.Specification
import spock.lang.Unroll

class KeysControllerEnabledSpec extends Specification {

    @Unroll("if micronaut.security.endpoints.keys.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.endpoints.keys.enabled=false security related beans are not loaded"(Class clazz, String description) {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.endpoints.keys.enabled': false,
        ])

        when:
        applicationContext.getBean(clazz)

        then:
        NoSuchBeanException e = thrown()
        e.message.contains('No bean of type [' + clazz.name + '] exists.')

        cleanup:
        applicationContext.close()

        where:
        clazz << [
                KeysController,
                KeysControllerConfiguration,
                KeysControllerConfigurationProperties,
        ]

        description = clazz.name
    }

    @Unroll
    void "#description loads if micronaut.security.endpoints.keys.enabled=true"(Class clazz, String description) {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.endpoints.keys.enabled': true]
        )

        expect:
        applicationContext.containsBean(clazz)

        cleanup:
        applicationContext.close()

        where:
        clazz << [KeysController, KeysControllerConfiguration, KeysControllerConfigurationProperties]
        description = clazz.name
    }
}
