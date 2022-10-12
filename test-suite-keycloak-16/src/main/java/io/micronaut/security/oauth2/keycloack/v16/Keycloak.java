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
package io.micronaut.security.oauth2.keycloack.v16;

import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

public class Keycloak {
    public static final String SYS_TESTCONTAINERS = "testcontainers";
    public static final String CLIENT_ID = "myclient";
    private static String clientSecret = UUID.randomUUID().toString();
    private static String issuer;
    private static GenericContainer keycloak;

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

    static void init() throws IOException, InterruptedException {
        if (keycloak == null) {
            if (OperatingSystem.getCurrent().isMacOs() && System.getProperty("os.arch") != null && System.getProperty("os.arch").equals("aarch64")) {
                keycloak = new GenericContainer(new ImageFromDockerfile("keycloak-m1", false).withFileFromClasspath("Dockerfile", "/Dockerfile.keycloak"));
            } else {
                keycloak = new GenericContainer("jboss/keycloak:16.1.1");
            }

            keycloak = keycloak.withExposedPorts(8080)
                    .withEnv(Map.of(
                            "KEYCLOAK_USER", "user",
                            "KEYCLOAK_PASSWORD", "password",
                            "DB_VENDOR", "H2"
                    ))
                    .waitingFor(new LogMessageWaitStrategy().withRegEx(".*Deployed \"keycloak-server.war\".*").withStartupTimeout(Duration.ofMinutes(5)));
            keycloak.start();
            keycloak.execInContainer("/opt/jboss/keycloak/bin/kcreg.sh config credentials --server http://localhost:8080/auth --realm master --user user --password password".split(" "));
            keycloak.execInContainer(("/opt/jboss/keycloak/bin/kcreg.sh create -s clientId=" + CLIENT_ID + " -s redirectUris=[\"http://" + getRedirectUriHost() + "*\"] -s secret=" + clientSecret).split(" "));
            int port = keycloak.getMappedPort(8080);
            Testcontainers.exposeHostPorts(port);
            issuer = "http://" + getHost() + ":" + port  + "/auth/realms/master";
        }
    }

    public static String getRedirectUriHost() {
        return TestContainersUtils.getHost();
    }

    public static String getHost() {
        return "localhost";
    }

    public static void destroy() {
        if (keycloak != null) {
            keycloak.stop();
        }
        keycloak = null;
        clientSecret = null;
        issuer = null;
    }
}
