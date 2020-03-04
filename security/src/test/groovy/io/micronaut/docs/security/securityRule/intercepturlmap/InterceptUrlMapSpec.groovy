/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.docs.security.securityRule.intercepturlmap

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.testutils.YamlAsciidocTagCleaner
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class InterceptUrlMapSpec extends Specification implements YamlAsciidocTagCleaner {

    String yamlConfig = '''\
//tag::yamlconfig[]
micronaut:
  security:
    intercept-url-map:
      -
        pattern: /images/*
        http-method: GET
        access:
          - isAnonymous() # <1>
      -
        pattern: /books
        access:
          - isAuthenticated() # <2>
      -
        pattern: /books/grails
        http-method: POST
        access:
          - ROLE_GRAILS # <3>
          - ROLE_GROOVY
      - 
        pattern: /books/grails
        http-method: PUT
        access: 
          - ROLE_ADMIN        
'''//end::yamlconfig[]

    @Shared
    Map<String, Object> ipPatternsMap = ['micronaut': [
            'security': [
                    'intercept-url-map' : [
                            [
                                    pattern: '/images/*',
                                    'http-method': 'GET',
                                    access: ['isAnonymous()']
                            ],
                            [
                                    pattern: '/books',
                                    access: ['isAuthenticated()']
                            ],
                            [
                                    pattern: '/books/grails',
                                    'http-method': 'POST',
                                    access: ['ROLE_GRAILS', 'ROLE_GROOVY']
                            ],
                            [
                                    pattern: '/books/grails',
                                    'http-method': 'PUT',
                                    access: ['ROLE_ADMIN']
                            ],
                    ]
            ]
    ]
    ]

    @Shared
    Map<String, Object> config = [
            'spec.name'                                : 'docsintercepturlmap',
            'endpoints.health.enabled'                 : true,
            'endpoints.health.sensitive'               : false,
            'micronaut.security.token.basic-auth.enabled'           : true,
    ] << flatten(ipPatternsMap)

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>, Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

    void "test accessing a non sensitive endpoint without authentication"() {
        when:
        def resp = client.toBlocking().exchange(HttpRequest.GET("/books")
                .basicAuth("user", "password"), String)

        then:
        noExceptionThrown()
        resp.body() == "Index Action"

        when:
        resp = client.toBlocking().exchange(HttpRequest.GET("/books"), String)

        then:
        def ex = thrown(HttpClientResponseException)
        ex.status == HttpStatus.UNAUTHORIZED

        when:
        resp = client.toBlocking().exchange(HttpRequest.GET("/books/grails"), String)

        then:
        ex = thrown(HttpClientResponseException)
        ex.status == HttpStatus.UNAUTHORIZED //no rule in place, so rejected

        when:
        resp = client.toBlocking().exchange(HttpRequest.GET("/books/grails").basicAuth("admin", "password"), String)

        then:
        ex = thrown(HttpClientResponseException)
        ex.status == HttpStatus.FORBIDDEN //no rule in place, so rejected

        when:
        resp = client.toBlocking().exchange(HttpRequest.POST("/books/grails", "").basicAuth("admin", "password"), String)

        then:
        ex = thrown(HttpClientResponseException)
        ex.status == HttpStatus.FORBIDDEN //lacks required roles

        when:
        resp = client.toBlocking().exchange(HttpRequest.PUT("/books/grails", "")
                .basicAuth("admin", "password"), String)

        then:
        noExceptionThrown()
        resp.body() == "Grails Action"

        when:
        Map m = new Yaml().load(cleanYamlAsciidocTag(yamlConfig))

        then:
        m == ipPatternsMap
    }
}
