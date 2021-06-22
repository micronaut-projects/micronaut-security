package io.micronaut.security.token.jwt.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.generator.RefreshTokenGenerator
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.token.validator.RefreshTokenValidator
import io.micronaut.security.testutils.ApplicationContextSpecification
import org.reactivestreams.Publisher
import spock.lang.Unroll

import jakarta.inject.Singleton

class OauthControllerEnabledSpec extends ApplicationContextSpecification {

    @Override
    String getSpecName() {
        'OauthControllerEnabledSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.endpoints.oauth.enabled': false,
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

    @Unroll("bean #description is not loaded if micronaut.security.endpoints.oauth.enabled=false")
    void "if micronaut.security.endpoints.oauth.enabled=false security related beans are not loaded"(Class clazz, String description) {
        expect:
        applicationContext.containsBean(AccessRefreshTokenGenerator)
        applicationContext.containsBean(RefreshTokenPersistence)
        applicationContext.containsBean(RefreshTokenValidator)

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

    @Requires(property = 'spec.name', value = 'OauthControllerEnabledSpec')
    @Singleton
    static class CustomRefreshTokenPersistence implements RefreshTokenPersistence {

        @Override
        Publisher<UserDetails> getUserDetails(String refreshToken) {
            return null
        }

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {

        }
    }
}
