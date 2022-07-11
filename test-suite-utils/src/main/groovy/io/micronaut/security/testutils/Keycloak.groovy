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

import dasniko.testcontainers.keycloak.KeycloakContainer
import org.testcontainers.Testcontainers
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy

import java.time.Duration

class Keycloak {
    static final String SYS_TESTCONTAINERS = "testcontainers"
    static final String VENDOR = "keycloak-18"
    private static String issuer
    static final String CLIENT_ID = "myclient"
    private static String clientSecret = UUID.randomUUID()
    static KeycloakContainer keycloak

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

    static Integer getPort() {
        String issuer = getIssuer()
        Integer.valueOf(issuer.substring(issuer.indexOf("localhost:") + "localhost:".length(),  issuer.indexOf("/realms")))
    }

    static void init() {
        if (keycloak == null) {

            keycloak = new KeycloakContainer()
                    .withAdminUsername("admin")
                    .withAdminPassword("admin")
                    .withExposedPorts(8080)
                    .withEnv(Map.of(
                            "KEYCLOAK_USER", "user",
                            "KEYCLOAK_PASSWORD", "password",
                            "DB_VENDOR", "H2")
                    )
                    .waitingFor(new LogMessageWaitStrategy().withRegEx(".*powered by Quarkus.*").withStartupTimeout(Duration.ofMinutes(5)))

            keycloak.start()
            keycloak.execInContainer("/opt/keycloak/bin/kcreg.sh config credentials " +
                    "--server http://localhost:8080/auth " +
                    "--realm master --user user --password password"
                            .split(" "))
            keycloak.execInContainer("/opt/keycloak/bin/kcreg.sh " +
                    "create -s clientId=$CLIENT_ID " +
                    "-s redirectUris=[\"http://${TestContainersUtils.host}*\"] " +
                    "-s secret=$clientSecret"
                            .split(" "))
            int port = keycloak.getMappedPort(8080)
            Testcontainers.exposeHostPorts(port)
            issuer = "http://" + getHost() + ":" + port  + "/realms/master"
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
