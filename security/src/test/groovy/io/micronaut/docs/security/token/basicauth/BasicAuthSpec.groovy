package io.micronaut.docs.security.token.basicauth

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification

class BasicAuthSpec extends Specification implements YamlAsciidocTagCleaner {

    @Shared
    Map<String, Object> config = [
            'spec.name' : 'docsbasicauth',
            'endpoints.beans.enabled'                 : true,
            'endpoints.beans.sensitive'               : true,
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

    @Ignore
    void "test /beans is secured but accesible if you supply valid credentials with Basic Auth"() {
        when:
        String token = 'dXNlcjpwYXNzd29yZA==' // user:passsword Base64
        client.toBlocking().exchange(HttpRequest.GET("/beans")
                .header("Authorization", "Basic ${token}".toString()), String)

        then:
        noExceptionThrown()
    }

    def "basicAuth() sets Authorization Header with Basic base64(username:password)"() {
        when:
        // tag::basicAuth[]
        HttpRequest request = HttpRequest.GET("/home").basicAuth('sherlock', 'password')
        // end::basicAuth[]

        then:
        request.headers.get('Authorization')
        request.headers.get('Authorization') == "Basic ${'sherlock:password'.bytes.encodeBase64().toString()}"
    }

    @Requires(property = 'spec.name', value = 'docsbasicauth')
    @Replaces(SensitiveEndpointRule.class)
    @Singleton
    static class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {
        SensitiveEndpointRuleReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor) {
            super(endpointSensitivityProcessor)
        }

        @Override
        protected Publisher<SecurityRuleResult> checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                                            @NonNull Authentication authentication,
                                                                            @NonNull ExecutableMethod<?, ?> method) {
            Mono.just(SecurityRuleResult.ALLOWED)
        }
    }
}
