/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.oauth2.keycloak.docker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

public final class Keycloak {

    private static final Logger LOG = LoggerFactory.getLogger(Keycloak.class);

    public static final String LOCALHOST = "http://localhost";
    public static final String HOST_TESTCONTAINERS_INTERNAL = "http://host.testcontainers.internal";
    public static final String SYS_TESTCONTAINERS = "testcontainers";

    public static final String CLIENT_ID = "myclient";
    public static final String TEST_USERNAME = "test";
    @SuppressWarnings("java:S2068")
    public static final String TEST_PASSWORD = "password";

    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.0.7";
    private static final int KEYCLOAK_HTTP_PORT = 8080;
    private static final String KEYCLOAK_RELATIVE_PATH = "/auth";

    private static final String ADMIN_USERNAME = "user";
    @SuppressWarnings("java:S2068")
    private static final String ADMIN_PASSWORD = "admin";
    private static final String REALM = "master";

    private static final String ADMIN_SERVER_IN_CONTAINER = "http://localhost:" + KEYCLOAK_HTTP_PORT + KEYCLOAK_RELATIVE_PATH;

    private static final String KCADM = "/opt/keycloak/bin/kcadm.sh";
    private static final String KC_CONFIG_PATH = "/tmp/kcadm.config";

    private static final Object LOCK = new Object();

    private static volatile GenericContainer<?> container;
    private static volatile String clientSecret;
    private static volatile String issuer;
    private static volatile Integer mappedHttpPort;

    private Keycloak() {
    }

    public static String getClientSecret() throws IOException, InterruptedException {
        ensureStarted();
        return clientSecret;
    }

    public static String getIssuer() throws IOException, InterruptedException {
        ensureStarted();
        return issuer;
    }

    public static int getPort() throws IOException, InterruptedException {
        ensureStarted();
        return mappedHttpPort;
    }

    static void init() throws IOException, InterruptedException {
        ensureStarted();
    }

    private static void ensureStarted() throws IOException, InterruptedException {
        if (container != null && container.isRunning()) {
            return;
        }
        synchronized (LOCK) {
            if (container != null && container.isRunning()) {
                return;
            }

            LOG.info("Initializing Keycloak container...");
            clientSecret = UUID.randomUUID().toString();

            container = new GenericContainer<>(KEYCLOAK_IMAGE)
                .withExposedPorts(KEYCLOAK_HTTP_PORT)
                .withEnv(Map.of(
                    "KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USERNAME,
                    "KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD,
                    "KC_HTTP_RELATIVE_PATH", KEYCLOAK_RELATIVE_PATH,
                    "KC_DB", "dev-file"
                ))
                .withCommand("start-dev")
                .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("KEYCLOAK"))
                // Wait for HTTP readiness (better than sleeps / log matching)
                .waitingFor(
                    Wait.forHttp(KEYCLOAK_RELATIVE_PATH + "/realms/" + REALM)
                        .forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(5))
                );

            container.start();

            mappedHttpPort = container.getMappedPort(KEYCLOAK_HTTP_PORT);
            issuer = LOCALHOST + ":" + mappedHttpPort + KEYCLOAK_RELATIVE_PATH + "/realms/" + REALM;

            // Needed so the Selenium (container) browser can reach Keycloak via host.testcontainers.internal:<mappedPort> on Linux.
            Testcontainers.exposeHostPorts(mappedHttpPort);

            kcadm("Authenticate kcadm",
                "config", "credentials",
                "--server", ADMIN_SERVER_IN_CONTAINER,
                "--realm", REALM,
                "--user", ADMIN_USERNAME,
                "--password", ADMIN_PASSWORD
            );

            // If you need a secret, this should NOT be a public client.
            kcadm("Create Client",
                "create", "clients",
                "-s", "clientId=" + CLIENT_ID,
                "-s", "redirectUris=[\"http://" + getRedirectUriHost() + "*\", \"http://localhost*\"]",
                "-s", "publicClient=false",
                "-s", "directAccessGrantsEnabled=true",
                "-s", "serviceAccountsEnabled=true",
                "-s", "attributes={\"post.logout.redirect.uris\": \"+\"}",
                "-s", "secret=" + clientSecret,
                "--realm", REALM
            );

            kcadm("Relax SSL Requirement",
                "update", "realms/" + REALM,
                "-s", "sslRequired=NONE",
                "--realm", REALM
            );

            kcadm("Create User",
                "create", "users",
                "-s", "username=" + TEST_USERNAME,
                "-s", "enabled=true",
                "--realm", REALM
            );

            kcadm("Set Password",
                "set-password",
                "--username", TEST_USERNAME,
                "--new-password", TEST_PASSWORD,
                "--realm", REALM
            );

            LOG.info("Keycloak ready. Issuer: {}", issuer);
        }
    }

    private static void kcadm(String taskName, String... args) throws IOException, InterruptedException {
        // Build: /opt/keycloak/bin/kcadm.sh <args> --config /tmp/kcadm.config
        String[] cmd = new String[args.length + 3];
        cmd[0] = KCADM;
        System.arraycopy(args, 0, cmd, 1, args.length);
        cmd[cmd.length - 2] = "--config";
        cmd[cmd.length - 1] = KC_CONFIG_PATH;

        exec(taskName, cmd);
    }

    private static void exec(String taskName, String... command) throws IOException, InterruptedException {
        if (container == null) {
            throw new IllegalStateException("Keycloak container is not started");
        }

        Container.ExecResult result = container.execInContainer(command);
        if (result.getExitCode() == 0) {
            return;
        }

        String debugMessage = String.format(
            "Failed to %s%nExit Code: %d%nCommand: %s%nSTDOUT:%n%s%nSTDERR:%n%s",
            taskName,
            result.getExitCode(),
            String.join(" ", command),
            result.getStdout(),
            result.getStderr()
        );
        throw new IllegalStateException(debugMessage);
    }

    public static String getRedirectUriHost() {
        return TestContainersUtils.getHost();
    }

    public static void destroy() {
        synchronized (LOCK) {
            if (container != null) {
                try {
                    container.stop();
                } catch (Exception e) {
                    LOG.warn("Failed stopping Keycloak container", e);
                }
            }
            container = null;
            clientSecret = null;
            issuer = null;
            mappedHttpPort = null;
        }
    }
}
