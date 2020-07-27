package io.micronaut.docs.security.token.propagation

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagatorConfiguration
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter
import io.micronaut.security.token.propagation.TokenPropagator
import io.micronaut.testutils.YamlAsciidocTagCleaner
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class TokenPropagationSpec extends Specification implements YamlAsciidocTagCleaner {

    String yamlConfig = '''\
//tag::yamlconfig[]
micronaut:
    application:
        name: gateway
    security:
        token:
            jwt:
                signatures:
                    secret:
                        generator:
                            secret: "pleaseChangeThisSecretForANewOne"
                            jws-algorithm: HS256
            propagation:
                header:
                    enabled: true
                    headerName: "Authorization"
                    prefix: "Bearer "
                enabled: true
                service-id-regex: "http://localhost:(8083|8081|8082)"                            
'''//end::yamlconfig[]





    @Shared
    Map<String, Object> propagationMap = [
            'micronaut': [
                    'application': [
                            'name': 'gateway',
                    ],
                    'security': [
                            'token': [
                                    'jwt': [
                                            'signatures': [
                                                    'secret': [
                                                        'generator': [
                                                                'secret': "pleaseChangeThisSecretForANewOne",
                                                                'jws-algorithm': 'HS256'
                                                        ]
                                                    ]
                                            ]
                                    ],
                                    'propagation': [
                                            'header': [
                                                    'enabled': true,
                                                    'headerName': 'Authorization',
                                                    'prefix': 'Bearer ',
                                            ],
                                            'enabled': true,
                                            'service-id-regex': 'http://localhost:(8083|8081|8082)'
                                    ]
                            ]
                    ]
            ]
    ]

    @Shared
    Map<String, Object> config = [
            'spec.name'                 : TokenPropagationSpec.class.simpleName
    ] << flatten(propagationMap)

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer,
            config as Map<String, Object>,
            Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

    void "test valid propagation configuration"() {
        when:
        embeddedServer.applicationContext.getBean(TokenPropagationHttpClientFilter)

        then:
        noExceptionThrown()

        when:
        embeddedServer.applicationContext.getBean(HttpHeaderTokenPropagator)

        then:
        noExceptionThrown()

        when:
        embeddedServer.applicationContext.getBean(HttpHeaderTokenPropagatorConfiguration)

        then:
        noExceptionThrown()

        when:
        Map m = new Yaml().load(cleanYamlAsciidocTag(yamlConfig))
        then:
        m == propagationMap
    }
}
