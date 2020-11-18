package io.micronaut.security.oauth2

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
            keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh create -s clientId=$CLIENT_ID -s redirectUris=[\"http://localhost*\"]".split(" "))
            Container.ExecResult result = keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh get $CLIENT_ID".split(" "))
            Map map = new ObjectMapper().readValue(result.getStdout(), Map.class)
            clientSecret = map.get("secret")
            issuer = "http://localhost:" + keycloak.getMappedPort(8080) + "/auth/realms/master"
        }
    }

    static void destroy(GenericContainer container) {
        if (container != null) {
            container.stop()
            container = null
        }
    }
}
