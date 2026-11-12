package io.micronaut.security.tests;

import io.micronaut.core.util.StringUtils;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

public class MySQL {

    public static final String MYSQL_9_2_0 = "mysql:9.2.0";
    private static MySQLContainer<?> mysql;

    public static Map<String, String> getProperties() {
        if (mysql == null) {
            mysql = new MySQLContainer<>(DockerImageName.parse(MYSQL_9_2_0));
            mysql.start();
            do {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            } while(!mysql.isRunning());
            return getProperties(mysql);
        } else {
            return getProperties(mysql);
        }
    }

    public static void close() {
        if (mysql != null) {
            mysql.stop();
        }
    }

    private static Map<String, String> getProperties(MySQLContainer container) {
        return Map.of(
            "jpa.default.reactive", StringUtils.TRUE,
            "jpa.default.entity-scan.packages[0]", "io.micronaut.security.tests.entity",
            "jpa.default.properties.hibernate.show-sql", StringUtils.TRUE,
            "jpa.default.properties.hibernate.hbm2ddl.auto", "update",
            "jpa.default.properties.hibernate.connection.db-type", "mysql",
            "jpa.default.properties.hibernate.connection.password", container.getPassword(),
            "jpa.default.properties.hibernate.connection.url", container.getJdbcUrl(),
            "jpa.default.properties.hibernate.connection.username", container.getUsername()
        );
    }
}
