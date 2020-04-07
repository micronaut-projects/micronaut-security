/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.utils

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class SecurityServiceSpecCustomRolesKey extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'
    static  final String controllerPath = "/securityutils"

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            (SPEC_NAME_PROPERTY): SecurityServiceSpec.class.simpleName,
            'micronaut.security.enabled': true,
            'micronaut.security.token.roles-name': 'customRoles',
    ], Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())


    void "verify SecurityService.isCurrentUserInRole() with custom roleKey"() {
        when:
        HttpRequest request = HttpRequest.GET("${controllerPath}/roles?role=ROLE_USER")
                .basicAuth("user2", "password")
        Boolean hasRole = client.toBlocking().retrieve(request, Boolean)

        then:
        hasRole

        when:
        request = HttpRequest.GET("${controllerPath}/roles?role=ROLE_ADMIN")
                .basicAuth("user2", "password")
        hasRole = client.toBlocking().retrieve(request, Boolean)

        then:
        !hasRole

        when:
        request = HttpRequest.GET("${controllerPath}/roles?role=ROLE_USER")
                .basicAuth("user3", "password")
        hasRole = client.toBlocking().retrieve(request, Boolean)

        then:
        !hasRole
    }



}
