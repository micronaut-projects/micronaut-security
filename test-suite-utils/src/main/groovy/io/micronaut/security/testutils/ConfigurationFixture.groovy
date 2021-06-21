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

interface ConfigurationFixture {
    default Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        if (TestContainersUtils.isGebUsingTestContainers()) {
            m['micronaut.security.token.jwt.cookie.cookie-secure'] = false
            m['micronaut.security.token.refresh.cookie.cookie-secure'] = false
        }
        m += loginModeCookie
        m += oauth2ClientConfiguration
        m
    }

    default String getOpenIdClientName() {
        'foo'
    }

    default String getSpecName() {
        null
    }

    default String getIssuer() {
        null
    }

    default Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'cookie']
    }

    default Map<String, Object> getOauth2ClientConfiguration() {
        Map m = [
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-id".toString()): 'XXXX',
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-secret".toString()): 'YYYY',
        ]
        if (issuer != null) {
            m[("micronaut.security.oauth2.clients.${openIdClientName}.openid.issuer".toString())] = issuer
        }
        m
    }
}
