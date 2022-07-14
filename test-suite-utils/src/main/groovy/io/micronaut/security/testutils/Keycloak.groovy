package io.micronaut.security.testutils

import dasniko.testcontainers.keycloak.KeycloakContainer
import org.testcontainers.Testcontainers

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

    private static exec(String... parts) {
        println "Running command: " + parts.join(" ")
        def result =  keycloak.execInContainer(parts)
        println "OUT: $result.stdout"
        println "ERR: $result.stderr"
        println "EXIT: $result.exitCode"
        assert result.exitCode == 0
    }

    static void init() {
        if (keycloak == null) {

            keycloak = new KeycloakContainer()
                    .withAdminUsername("admin")
                    .withAdminPassword("admin")
                    .withExposedPorts(8080)
                    .withEnv(DB_VENDOR: "H2")

            keycloak.start()
            // Login
            exec("/opt/keycloak/bin/kcadm.sh",
                    "config", "credentials",
                    "--server", "http://localhost:8080",
                    "--realm", "master",
                    "--user", "admin",
                    "--password", "admin")
            // Add user
            exec("/opt/keycloak/bin/kcadm.sh",
                    "create", "users",
                    "-s", "username=user",
                    "-s", "enabled=true",
                    "-o",
                    "--fields", "id,username")
            // Set user password
            exec("/opt/keycloak/bin/kcadm.sh",
                    "set-password",
                    "--username", "user",
                    "--new-password", "password")
            // Add client
            exec("/opt/keycloak/bin/kcreg.sh",
                    "create",
                    "--server", "http://localhost:8080",
                    "--realm", "master",
                    "--user", "admin",
                    "--password", "admin",
                    "-s", "clientId=$CLIENT_ID",
                    "-s", "redirectUris=[\"http://${redirectUriHost}*\"]",
                    "-s", "secret=$clientSecret")
            int port = keycloak.getMappedPort(8080)
            Testcontainers.exposeHostPorts(port)
            issuer = "http://$host:$port/realms/master"
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
