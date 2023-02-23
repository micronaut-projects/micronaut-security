package io.micronaut.docs.security.securityRule.builtinendpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import jakarta.inject.Singleton
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class BuiltInEndpointsSpec extends Specification implements YamlAsciidocTagCleaner {

    String yamlConfig = '''\
//tag::yamlconfig[]
endpoints:
  beans:
    enabled: true
    sensitive: true
  info:
    enabled: true
    sensitive: false
'''//end::yamlconfig[]

    @Shared
    Map<String, Object> endpointsMap = [
            endpoints: [
                    beans: [
                            enabled                : true,
                            sensitive              : true,
                    ],
                    info: [
                            enabled                : true,
                            sensitive              : false,
                    ],
            ]
    ]

    @Shared
    Map<String, Object> config = ['spec.name': 'BuiltInEndpointsSpec'] << flatten(endpointsMap)

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL)

    void "test accessing a non sensitive endpoint without authentication"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/info"))

        then:
        noExceptionThrown()

        when:
        Map m = new Yaml().load(cleanYamlAsciidocTag(yamlConfig))

        then:
        m == endpointsMap
    }

    void "test accessing a sensitive endpoint with authentication but no SensitiveEndpointRule replacement throws an exception"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/beans"))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.toBlocking().exchange(HttpRequest.GET("/beans").basicAuth("user", "password"), Argument.of(Map), Argument.of(Map))

        then:
        HttpClientResponseException ex = thrown()

        when:
        Map m = ex.response.body()

        then:
        m._embedded.errors == [[message: "Internal Server Error: ${SensitiveEndpointRule.NON_REPLACED_SECURITY_ERROR_MESSAGE}"]]
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'BuiltInEndpointsSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
