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

import org.testcontainers.Testcontainers
import org.testcontainers.containers.Container
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper

import java.time.Duration

class Keycloak {
    static final String SYS_TESTCONTAINERS = "testcontainers"
    static final String CLIENT_ID = "myclient"
    private static String clientSecret
    private static String issuer
    static GenericContainer keycloak

    static String getClientSecret() {
        if (clientSecret == null) {
            init()
        }
        clientSecret
    }

    static String getIssuer() {
        if (issuer == null) {
            init()
        }
        issuer
    }
    static void init() {
        if (keycloak == null) {
            keycloak = new GenericContainer("jboss/keycloak:8.0.0")
                    .withExposedPorts(8080)
                    .withEnv([
                            KEYCLOAK_USER: 'user',
                            KEYCLOAK_PASSWORD: 'password',
                            DB_VENDOR: 'H2',
                    ])
                    .waitingFor(new LogMessageWaitStrategy().withRegEx(".*Deployed \"keycloak-server.war\".*").withStartupTimeout(Duration.ofMinutes(2)))
            keycloak.start()
            keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh config credentials --server http://localhost:8080/auth --realm master --user user --password password".split(" "))
            keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh create -s clientId=$CLIENT_ID -s redirectUris=[\"http://${getRedirectUriHost()}*\"]".split(" "))
            Container.ExecResult result = keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh get $CLIENT_ID".split(" "))
            Map map = new ObjectMapper()
                    .readValue(result.getStdout(), Map.class)
            clientSecret = map.get("secret")
            int port = keycloak.getMappedPort(8080)
            Testcontainers.exposeHostPorts(port)
            issuer = "http://" + getHost() + ":" + port  + "/auth/realms/master"
        }
    }

    static String getRedirectUriHost() {
        TestContainersUtils.host
    }

    static String getHost() {
        'localhost'
    }

    static void destroy() {
        if (keycloak != null) {
            keycloak.stop()
        }
        keycloak = null
        clientSecret = null
        issuer = null
    }
}
