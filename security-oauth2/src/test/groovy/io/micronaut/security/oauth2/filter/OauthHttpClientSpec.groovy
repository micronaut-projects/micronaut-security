/*
 *
 *  * Copyright 2017-2019 original authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package io.micronaut.security.oauth2.filter

import io.micronaut.context.ApplicationContext
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.oauth2.grants.GrantType
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class OauthHttpClientSpec extends Specification {
    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(
            ['micronaut.security.oauth2'               : true,
             'micronaut.security.oauth2.clients.oauth2': oauthConfig()
            ])

    @Shared
    @Client(id = "oauth2")
    RxHttpClient markedClient = embeddedServer.applicationContext.getBean(RxHttpClient)


    void "filter should be applied only to annotated clients "() {
        expect:
        markedClient.toBlocking().exchange(embeddedServer.host) == "Intercepted"
    }


    private OauthClientConfigurationProperties oauthConfig() {
        def config = new OauthClientConfigurationProperties()
        def tokenEndpoint = new OauthClientConfigurationProperties.TokenEndpointConfigurationProperties()

        tokenEndpoint.url = "https://github.com/login/oauth/access_token"

        config.clientId = "clientId"
        config.clientSecret = "clientSecret"
        config.token = tokenEndpoint
        config.grantType = GrantType.CLIENT_CREDENTIALS

        return config
    }
}
