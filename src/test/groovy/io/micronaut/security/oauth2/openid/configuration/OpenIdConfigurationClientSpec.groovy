package io.micronaut.security.oauth2.openid.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class OpenIdConfigurationClientSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OpenIdConfigurationClient is disabled by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY):getClass().simpleName,
                'micronaut.security.enabled': true,
        ], Environment.TEST)

        when:
        context.getBean(OpenIdConfigurationClient)

        then:
        thrown(NoSuchBeanException)

        cleanup:
        context.close()
    }

    void "OpenIdConfigurationClient bean is loaded if micronaut.security.oauth2.openid.issuer is set"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/auth0-openid-configuration.json'
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson,
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.openid.issuer': mockHttpServerUrl
        ], Environment.TEST)

        when:
        context.getBean(OpenIdConfigurationClient)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdConfigurationFactory)

        then:
        noExceptionThrown()

        // You need to attempt to retrieve a class bean created by the factory in order for factory method to kick off
        when:
        context.getBean(OpenIdConfiguration)

        then:
        noExceptionThrown()

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }
}
