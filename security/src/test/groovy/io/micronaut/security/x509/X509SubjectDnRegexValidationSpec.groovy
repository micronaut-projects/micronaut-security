package io.micronaut.security.x509

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.BeanInstantiationException
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class X509SubjectDnRegexValidationSpec extends Specification {

    private static final String PROPERTY = 'micronaut.security.x509.subject-dn-regex'

    void "starting the server with a subject DN regex with #description fails with a ConfigurationException"() {
        when:
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'micronaut.security.x509.enabled': true,
                (PROPERTY)                       : regex,
        ])

        then:
        Throwable e = thrown()
        ConfigurationException configurationException = findConfigurationException(e)
        configurationException
        configurationException.message.contains(PROPERTY)
        configurationException.message.contains(regex)

        cleanup:
        server?.stop()

        where:
        description             | regex
        'zero capturing groups' | 'CN=.*?(?:,|$)'
        'two capturing groups'  | '(CN)=(.*?)(?:,|$)'
    }

    void "starting the application context with a subject DN regex with #description fails with a ConfigurationException"() {
        when:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.x509.enabled': true,
                (PROPERTY)                       : regex,
        ])

        then:
        BeanInstantiationException e = thrown()
        ConfigurationException configurationException = findConfigurationException(e)
        configurationException
        configurationException.message.contains(PROPERTY)
        configurationException.message.contains(regex)

        cleanup:
        ctx?.stop()

        where:
        description             | regex
        'zero capturing groups' | 'CN=.*?(?:,|$)'
        'two capturing groups'  | '(CN)=(.*?)(?:,|$)'
    }

    void "a subject DN regex with exactly one capturing group is accepted"() {
        when:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.x509.enabled': true,
                (PROPERTY)                       : regex,
        ])

        then:
        noExceptionThrown()
        ctx.getBean(X509AuthenticationFetcher)
        ctx.getBean(X509Configuration).subjectDnRegex == regex

        cleanup:
        ctx?.stop()

        where:
        regex << [X509ConfigurationProperties.DEFAULT_SUBJECT_DN_REGEX, 'OU=(.*?)(?:,|$)', 'CN=([^,]+)(?:,|$)']
    }

    private static ConfigurationException findConfigurationException(Throwable t) {
        Throwable current = t
        while (current != null) {
            if (current instanceof ConfigurationException) {
                return current
            }
            current = current.cause
        }
        null
    }
}
