package io.micronaut.docs.security.securityRule

import io.micronaut.context.ApplicationContext
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.rules.IpPatternsRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.security.token.RolesFinder
import io.micronaut.web.router.RouteMatch
import org.reactivestreams.Publisher
import org.yaml.snakeyaml.Yaml
import reactor.core.publisher.Mono
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
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

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

    void "If HttpRequest::getRemoteAddress throws a IllegalArgumentException IpPatternRule evaluates to UNKNOWN"() {
        given:
        def rolesFinder = Mock(RolesFinder)
        def securityConfiguration = Stub(SecurityConfiguration) {
            getIpPatterns() >> Collections.singletonList('0.0.0.0')
        }
        IpPatternsRule patternsRule = new IpPatternsRule(rolesFinder, securityConfiguration)
        def request = Stub(HttpRequest) {
            getRemoteAddress() >> { throw new IllegalArgumentException() }
        }
        def routeMatch = Mock(RouteMatch)
        def authentication = Mock(Authentication)

        when:
        Publisher<SecurityRuleResult> securityRuleResultPublisher = patternsRule.check(request, authentication)

        then:
        noExceptionThrown()
        SecurityRuleResult.UNKNOWN == Mono.from(securityRuleResultPublisher).block()
    }
}
