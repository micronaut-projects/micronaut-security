package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import org.testcontainers.containers.Container
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper

import java.time.Duration

trait OpenIDIntegrationSpec {

    static final String CLIENT_ID = "myclient"
    static String CLIENT_SECRET
    static String ISSUER
    static GenericContainer keycloak

    static {
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
        CLIENT_SECRET = map.get("secret")
        ISSUER = "http://localhost:" + keycloak.getMappedPort(8080) + "/auth/realms/master"
    }

    ApplicationContext startContext(Map<String, Object> configuration = getConfiguration()) {
        return ApplicationContext.run(configuration, "test")
    }

    Map<String, Object> getConfiguration() {
        Map<String, Object> config = new HashMap<>()
        config.put("spec.name", this.getClass().getSimpleName())
        return config
    }

}
