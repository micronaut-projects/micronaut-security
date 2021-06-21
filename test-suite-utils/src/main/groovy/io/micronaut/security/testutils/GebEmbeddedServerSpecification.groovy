/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.testutils

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.testcontainers.Testcontainers
import spock.lang.AutoCleanup
import spock.lang.Shared

abstract class GebEmbeddedServerSpecification extends GebSpec implements ConfigurationFixture {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = embeddedServer.applicationContext

    @Shared
    @AutoCleanup
    HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.getURL())

    @Shared
    BlockingHttpClient client = httpClient.toBlocking()


    @Override
    Browser getBrowser() {
        Browser b = super.getBrowser()
        if (embeddedServer && !b.baseUrl) {
            b.baseUrl = baseUrl
        }
        b
    }

    String getProtocol() {
        'http'
    }

    String getHost() {
        TestContainersUtils.host
    }

    String getPort() {
        if (TestContainersUtils.isGebUsingTestContainers()) {
            Testcontainers.exposeHostPorts(embeddedServer.port)
        }
        embeddedServer.port
    }

    String getBaseUrl() {
        "$protocol://$host:$port"
    }
}
