package io.micronaut.docs.jwks

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.security.token.jwt.signature.jwks.HttpClientJwksClient
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class JwksSpec extends Specification implements YamlAsciidocTagCleaner {

    String yamlSecurityConfig = """
#tag::yamljwksconfig[]
micronaut:
  security:
    token:
      jwt:
        signatures:
          jwks:
            awscognito:
              url: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-XXXX/.well-known/jwks.json'
#end::yamljwksconfig[]
"""

    String yamlServiceClientConfig = """
#tag::yamlserviceclientconfig[]
micronaut:
  http:
    services:
      awscognito:
        url: 'https://cognito-idp.eu-west-1.amazonaws.com'
        proxy-type: 'http'
        proxy-address: 'proxy.company.net:8080'
  security:
    token:
      jwt:
        signatures:
          jwks:
            awscognito:
              url: '/eu-west-XXXX/.well-known/jwks.json'
#end::yamlserviceclientconfig[]
"""

    @Shared
    Map<String, Object> configMap = [
            'micronaut': [
                    'security': [
                            'token': [
                                    'jwt': [
                                            'signatures': [
                                                    'jwks': [
                                                            'awscognito': [
                                                                    'url': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-XXXX/.well-known/jwks.json'
                                                            ]
                                                    ]
                                            ]
                                    ]
                            ]
                    ]
            ]
    ]

    @Shared
    Map<String, Object> serviceClientConfigMap = [
            'micronaut': [
                    'http': [
                            'services' : [
                                    'awscognito' : [
                                            'url' : 'https://cognito-idp.eu-west-1.amazonaws.com',
                                            'proxy-type' : 'http',
                                            'proxy-address' : 'proxy.company.net:8080'
                                    ]
                            ]
                    ],
                    'security': [
                            'token': [
                                    'jwt': [
                                            'signatures': [
                                                    'jwks': [
                                                            'awscognito': [
                                                                    'url': '/eu-west-XXXX/.well-known/jwks.json'
                                                            ]
                                                    ]
                                            ]
                                    ]
                            ]
                    ]
            ]
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': 'docjkwsSpec',
    ] << flatten(configMap), Environment.TEST)

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServiceClientServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': 'docjkwsSpec',
    ] << flatten(serviceClientConfigMap), Environment.TEST)

    void "JwksSignature bean exists in context"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlSecurityConfig)) == configMap

        and:
        embeddedServer.applicationContext.containsBean(JwksSignature)
    }

    void "JwksClient bean exists in context"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlServiceClientConfig)) == serviceClientConfigMap

        and:
        embeddedServiceClientServer.applicationContext.containsBean(HttpClientJwksClient)
    }
}
