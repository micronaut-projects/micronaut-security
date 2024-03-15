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
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

public class Keycloak {

    private static final Logger LOG = LoggerFactory.getLogger(Keycloak.class);

    public static final String LOCALHOST = "http://localhost";
    public static final String HOST_TESTCONTAINERS_INTERNAL = "http://host.testcontainers.internal";
    public static final String SYS_TESTCONTAINERS = "testcontainers";
    public static final String CLIENT_ID = "myclient";
    public static final String TEST_USERNAME = "test";
    @SuppressWarnings("java:S2068") // Passwords are for testing an ephemeral container
    public static final String TEST_PASSWORD = "password";

    private static final String ADMIN_USERNAME = "user";
    @SuppressWarnings("java:S2068") // Passwords are for testing an ephemeral container
    private static final String ADMIN_PASSWORD = "bitnami";
    private static final String REALM = "master";
    private static final String ADMIN_SERVER = "http://localhost:8080/auth";
    private static String clientSecret = UUID.randomUUID().toString();
    private static String issuer;
    private static GenericContainer<?> container;

    private Keycloak() {
    }

    public static String getClientSecret() throws IOException, InterruptedException {
        if (clientSecret == null) {
            init();
        }
        return clientSecret;
    }

    public static String getIssuer() throws IOException, InterruptedException {
        if (issuer == null) {
            init();
        }
        return issuer;
    }

    public static Integer getPort() throws IOException, InterruptedException {
        String issuer = getIssuer();
        return Integer.valueOf(issuer.substring(issuer.indexOf("localhost:") + "localhost:".length(),  issuer.indexOf("/auth/realms")));
    }

    // Tell sonar I know I'm printing out, I don't want to close the container immediately, and adding constants for all the strings makes it less readable.
    @SuppressWarnings({"java:S106", "java:S2095", "java:S1192"})
    static void init() throws IOException, InterruptedException {
        if (container == null) {
            container = new GenericContainer<>("bitnami/keycloak:23")
                .withExposedPorts(8080)
                .withEnv(Map.of(
                    "KEYCLOAK_DATABASE_VENDOR", "h2",
                    "KC_HTTP_RELATIVE_PATH", "/auth", // https://github.com/micronaut-projects/micronaut-security/issues/1024
                    "KC_SPI_LOGIN_PROTOCOL_OPENID_CONNECT_LEGACY_LOGOUT_REDIRECT_URI", "true", // https://github.com/micronaut-projects/micronaut-security/issues/1024
                    "KC_SPI_LOGIN_PROTOCOL_OPENID_CONNECT_SUPPRESS_LOGOUT_CONFIRMATION_SCREEN", "true", // https://github.com/micronaut-projects/micronaut-security/issues/1024
                    "KC_DB", "dev-file"
                ))
                .withLogConsumer(outputFrame -> System.out.print("[--KEYCLOAK--] " + outputFrame.getUtf8String()))
                .waitingFor(new LogMessageWaitStrategy().withRegEx(".*Running the server in development mode. DO NOT use this configuration in production.*").withStartupTimeout(Duration.ofMinutes(5)));
            container.start();

            Container.ExecResult execResult = container.execInContainer(
                "/opt/bitnami/keycloak/bin/kcreg.sh",
                "config", "credentials",
                "--config", "/tmp/kcreg.config",
                "--server", ADMIN_SERVER,
                "--realm", REALM,
                "--user", ADMIN_USERNAME, "--password", ADMIN_PASSWORD
            );
            if (execResult.getExitCode() != 0) {
                throw new IllegalStateException("Failed to configure credentials " + execResult.getStderr());
            }

            LOG.info(execResult.getStdout());

            execResult = container.execInContainer(
                "/opt/bitnami/keycloak/bin/kcreg.sh",
                "create",
                "--config", "/tmp/kcreg.config",
                "-s", "clientId=" + CLIENT_ID,
                "-s", "redirectUris=[\"http://" + getRedirectUriHost() + "*\", \"http://localhost*\"]",
                "-s", "secret=" + clientSecret
            );

            if (execResult.getExitCode() != 0) {
                throw new IllegalStateException("Failed to configure client " + execResult.getStderr());
            }

            LOG.info(execResult.getStdout());

            execResult = container.execInContainer(
                "/opt/bitnami/keycloak/bin/kcadm.sh",
                "create", "users",
                "-s", "username=" + TEST_USERNAME,
                "-s", "enabled=true",
                "--realm", REALM,
                "--server", ADMIN_SERVER,
                "--user", ADMIN_USERNAME, "--password", ADMIN_PASSWORD
            );

            if (execResult.getExitCode() != 0) {
                throw new IllegalStateException("Failed to create test user " + execResult.getStderr());
            }

            LOG.info(execResult.getStdout());

            execResult = container.execInContainer(
                "/opt/bitnami/keycloak/bin/kcadm.sh",
                "set-password",
                "--username", TEST_USERNAME,
                "--new-password", TEST_PASSWORD,
                "--realm", REALM,
                "--server", ADMIN_SERVER,
                "--user", ADMIN_USERNAME, "--password", ADMIN_PASSWORD
            );

            if (execResult.getExitCode() != 0) {
                throw new IllegalStateException("Failed to set password for test user " + execResult.getStderr());
            }

            LOG.info(execResult.getStdout());

            int port = container.getMappedPort(8080);
            Testcontainers.exposeHostPorts(port);
            issuer = "http://localhost:" + port  + "/auth/realms/master";
        }
    }

    public static String getRedirectUriHost() {
        return TestContainersUtils.getHost();
    }

    public static void destroy() {
        if (container != null) {
            container.stop();
        }
        container = null;
        clientSecret = null;
        issuer = null;
    }
}
