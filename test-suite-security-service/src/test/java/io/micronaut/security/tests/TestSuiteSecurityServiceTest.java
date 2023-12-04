package io.micronaut.security.tests;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.MySQLContainer;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "jpa.default.reactive", value = StringUtils.TRUE)
@Property(name = "jpa.default.entity-scan.packages[0]", value = "io.micronaut.security.tests.entity")
@Property(name = "jpa.default.properties.hibernate.show-sql", value = StringUtils.TRUE)
@Property(name = "jpa.default.properties.hibernate.hbm2ddl.auto", value = "update")
@Property(name = "jpa.default.properties.hibernate.connection.db-type", value = "mysql")
@MicronautTest(transactional = false)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TestSuiteSecurityServiceTest implements TestPropertyProvider {
    static final MySQLContainer MY_SQL_CONTAINER;

    static {
        MY_SQL_CONTAINER = new MySQLContainer();
        MY_SQL_CONTAINER.start();
    }

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Map.of(
        "jpa.default.properties.hibernate.connection.password", MY_SQL_CONTAINER.getPassword(),
        "jpa.default.properties.hibernate.connection.url", MY_SQL_CONTAINER.getJdbcUrl(),
        "jpa.default.properties.hibernate.connection.username", MY_SQL_CONTAINER.getUsername());
    }

    @Test
    void securityServiceInReactiveChain(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        URI uri = UriBuilder.of("/foo").path("mono").build();
        String principal = assertDoesNotThrow(() ->
                client.retrieve(HttpRequest.GET(uri)
                        .accept(MediaType.TEXT_PLAIN)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer xxx")));
        assertEquals("sherlock", principal);
    }

    @AfterAll
    static void afterAll() {
        MY_SQL_CONTAINER.close();
    }
}
