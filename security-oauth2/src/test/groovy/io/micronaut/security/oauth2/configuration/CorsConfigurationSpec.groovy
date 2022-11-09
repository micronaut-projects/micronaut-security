package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.http.server.HttpServerConfiguration
import io.micronaut.json.convert.JsonConverterRegistrar
import spock.lang.Issue
import spock.lang.Specification

class CorsConfigurationSpec extends Specification {
    @Issue('https://github.com/micronaut-projects/micronaut-security/issues/1130')
    def 'cors configuration should be parsed correctly with oauth2 on classpath'() {
        given:
        def ctx = ApplicationContext.run([
                'micronaut.server.cors.enabled': true,
                'micronaut.server.cors.configurations.web.exposedHeaders': ['Location'],
                'micronaut.server.cors.configurations.web.allowCredentials': true,
        ])

        expect:
        JsonConverterRegistrar.class.name
        ctx.getBean(HttpServerConfiguration).cors.enabled
        ctx.getBean(HttpServerConfiguration).cors.configurations.size() == 1
        ctx.getBean(HttpServerConfiguration).cors.configurations.keySet().iterator().next() == 'web'
        ctx.getBean(HttpServerConfiguration).cors.configurations.values().iterator().next().exposedHeaders.size() == 1
    }
}
