package io.micronaut.security.oauth2.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.oauth2.configuration.OauthConfiguration
import io.micronaut.security.oauth2.handlers.AuthorizationResponseHandler

import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpointConfiguration
import spock.lang.Shared
import spock.lang.Specification

class AuthorizationCodeControllerDisableSpec extends Specification {

    static final String SPEC_NAME = 'spec.name'
    @Shared
    Map<String, Object> config = [
            (SPEC_NAME)                                   : getClass().simpleName,
            'micronaut.security.enabled'                  : true,
            'micronaut.security.oauth2.client-id'         : 'XXX',
            'micronaut.security.oauth2.token.redirect-uri': 'http://localhost:8080',
            'micronaut.security.oauth2.token.url'         : 'http://localhost:8080',
    ]

    void "AuthorizationCodeController can be disabled with micronaut.security.endpoints.authcode.enabled=false"() {
        given:
        Map<String, Object> conf = [
                'micronaut.security.endpoints.authcode.enabled': false,
        ]
        conf.putAll(config)
        ApplicationContext context = ApplicationContext.run(conf, Environment.TEST)

        when:
        context.getBean(AuthorizationCodeController)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }

    void "AuthorizationCodeController is loaded by default"() {
        given:
        Map<String, Object> conf = [:]
        conf.putAll(config)
        ApplicationContext context = ApplicationContext.run(conf, Environment.TEST)

        expect:
        context.containsBean(AuthorizationResponseHandler)

        and:
        context.containsBean(AuthorizationCodeController)

        and:
        context.containsBean(OpenIdProviderMetadata)

        and:
        context.containsBean(TokenEndpointConfiguration)

        and:
        context.containsBean(OauthConfiguration)

        cleanup:
        context.close()
    }

    void "AuthorizationCodeController can be disabled with micronaut.security.oauth2.authorization.response-type=id-token"() {
        given:
        Map<String, Object> conf = ['micronaut.security.oauth2.authorization.response-type': 'id-token']
        conf.putAll(config)
        ApplicationContext context = ApplicationContext.run(conf, Environment.TEST)

        when:
        context.getBean(AuthorizationCodeController)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }

    void "AuthorizationCodeController can be disabled with micronaut.security.oauth2.token.grant-type=implicit"() {
        given:
        Map<String, Object> conf = ['micronaut.security.oauth2.token.grant-type': 'implicit']
        conf.putAll(config)
        ApplicationContext context = ApplicationContext.run(conf, Environment.TEST)

        when:
        context.getBean(AuthorizationCodeController)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }
}
