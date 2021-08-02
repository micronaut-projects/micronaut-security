package io.micronaut.docs.security.securityRule

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class IpPatternSpec extends Specification implements YamlAsciidocTagCleaner {

    String yamlConfig = '''\
//tag::yamlconfig[]
micronaut:
  security:
    ip-patterns:
      - 127.0.0.1
      - 192.168.1.*
'''//end::yamlconfig[]


    @Shared
    Map<String, Object> ipPatternsMap = ['micronaut': [
            'security': [
                    'ip-patterns' : ['127.0.0.1', '192.168.1.*']
            ]
        ]
    ]

    @Shared
    Map<String, Object> config = [
            'endpoints.beans.enabled'                 : true,
            'endpoints.beans.sensitive'               : false,
    ] << flatten(ipPatternsMap)

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>, Environment.TEST)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

    void "test accessing a resource from a whitelisted IP is successful"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/beans"), String)

        then:
        noExceptionThrown()

        when:
        Map m = new Yaml().load(cleanYamlAsciidocTag(yamlConfig))
        then:
        m == ipPatternsMap
    }
}
