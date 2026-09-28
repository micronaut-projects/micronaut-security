package io.micronaut.security.propagation

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.security.token.propagation.TokenPropagationConfigurationProperties
import spock.lang.Specification

import java.util.regex.Pattern

class TokenPropagationRegexConfigurationSpec extends Specification {

    void "an invalid #property fails context startup with a message naming the property"(String property) {
        when:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.token.propagation.enabled': true,
                ("micronaut.security.token.propagation.${property}".toString()): '(',
        ])
        ctx.getBean(TokenPropagationConfigurationProperties)

        then:
        Exception e = thrown()
        Throwable cause = e
        while (cause != null && !(cause instanceof ConfigurationException)) {
            cause = cause.cause
        }
        cause != null
        cause.message.contains(property)
        cause.message.contains("'('")

        cleanup:
        ctx?.close()

        where:
        property << ['service-id-regex', 'uri-regex']
    }

    void "a valid regex is bound at startup and matches"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.token.propagation.enabled': true,
                'micronaut.security.token.propagation.service-id-regex': 'foo-.*',
                'micronaut.security.token.propagation.uri-regex': 'https://example\\.com/.*',
        ])

        when:
        TokenPropagationConfigurationProperties config = ctx.getBean(TokenPropagationConfigurationProperties)

        then:
        config.serviceIdRegex == 'foo-.*'
        config.serviceIdPattern.matcher('foo-bar').matches()
        !config.serviceIdPattern.matcher('bar').matches()
        config.uriPattern.matcher('https://example.com/api').matches()

        cleanup:
        ctx.close()
    }

    void "invalid regex in setter throws ConfigurationException"() {
        given:
        TokenPropagationConfigurationProperties config = new TokenPropagationConfigurationProperties()

        when:
        config.setServiceIdRegex('(')

        then:
        ConfigurationException e = thrown()
        e.message.contains('service-id-regex')
        config.serviceIdRegex == null
        config.serviceIdPattern == null

        when:
        config.setUriRegex('[')

        then:
        ConfigurationException e2 = thrown()
        e2.message.contains('uri-regex')
        config.uriPattern == null
    }

    void "pattern getters return the same precompiled instance and track setter updates"() {
        given:
        TokenPropagationConfigurationProperties config = new TokenPropagationConfigurationProperties()

        expect:
        config.serviceIdPattern == null
        config.uriPattern == null

        when:
        config.setServiceIdRegex('a.*')
        config.setUriRegex('/b.*')
        Pattern serviceId = config.serviceIdPattern
        Pattern uri = config.uriPattern

        then:
        serviceId.pattern() == 'a.*'
        uri.pattern() == '/b.*'
        config.serviceIdPattern.is(serviceId)
        config.uriPattern.is(uri)

        when:
        config.setServiceIdRegex(null)
        config.setUriRegex('/c.*')

        then:
        config.serviceIdPattern == null
        config.uriPattern.pattern() == '/c.*'
    }
}
