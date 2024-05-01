package io.micronaut.docs.jwks

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature
import io.micronaut.security.token.jwt.signature.jwks.HttpClientJwksClient

import io.micronaut.security.token.jwt.signature.jwks.ResourceRetrieverJwksClient
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

    String yamlServiceFallbackClientConfig = """
#tag::yamlservicefallbackclientconfig[]
micronaut:
  security:
    token:
      jwt:
        signatures:
          jwks-client:
            http-client:
              enabled: false
          jwks:
            awscognito:
              url: '/eu-west-XXXX/.well-known/jwks.json'
#end::yamlservicefallbackclientconfig[]
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
    Map<String, Object> serviceFallbackClientConfigMap = [
            'micronaut': [
                    'security': [
                            'token': [
                                    'jwt': [
                                            'signatures': [
                                                    'jwks-client': [
                                                            'http-client': [
                                                                    'enabled': false
                                                            ]
                                                    ],
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

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServiceFallbackClientServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': 'docjkwsSpec',
    ] << flatten(serviceFallbackClientConfigMap), Environment.TEST)

    void "JwksSignature bean exists in context"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlSecurityConfig)) == configMap

        and:
        embeddedServer.applicationContext.containsBean(ReactiveJwksSignature)
    }

    void "HttpClientJwksClient bean exists in context"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlServiceClientConfig)) == serviceClientConfigMap

        and:
        embeddedServiceClientServer.applicationContext.containsBean(HttpClientJwksClient)
    }

    void "ResourceRetrieverJwksClient bean exists in context and HttpClientJwksClient is disabled"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlServiceFallbackClientConfig)) == serviceFallbackClientConfigMap

        and:
        embeddedServiceFallbackClientServer.applicationContext.containsBean(ResourceRetrieverJwksClient)
        !embeddedServiceFallbackClientServer.applicationContext.containsBean(HttpClientJwksClient)
    }
}
