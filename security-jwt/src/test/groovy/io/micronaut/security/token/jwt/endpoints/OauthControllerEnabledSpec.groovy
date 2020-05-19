package io.micronaut.security.token.jwt.endpoints


import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class OauthControllerEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.endpoints.oauth.enabled': false,]
    }

    @Unroll("bean #description is not loaded if micronaut.security.endpoints.oauth.enabled=false")
    void "if micronaut.security.endpoints.oauth.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        applicationContext.getBean(clazz)

        then:
        NoSuchBeanException e = thrown()
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                OauthController,
                OauthControllerConfiguration,
                OauthControllerConfigurationProperties,
        ]

        description = clazz.simpleName
    }

}
