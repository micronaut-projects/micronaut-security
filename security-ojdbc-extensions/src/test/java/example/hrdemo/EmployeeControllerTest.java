package example.hrdemo;

import example.hrdemo.model.Employee;
import example.hrdemo.testcontainers.Oracle;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.test.annotation.Sql;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Singleton;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.reactivestreams.Publisher;

import java.math.BigDecimal;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.AssertionsKt.assertNull;

@Sql(value = {"classpath:seed.sql"}, phase = Sql.Phase.BEFORE_ALL)
@Sql(value = {"classpath:seed-rollback.sql"}, phase = Sql.Phase.AFTER_ALL)
@Property(name = "spec.name", value = "EmployeeControllerTest")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EmployeeControllerTest implements TestPropertyProvider {
    @Test
    void rendersEmployeeAsJson(@Client("/") HttpClient httpClient) throws Exception {
        BlockingHttpClient client = httpClient.toBlocking();

        // Marvin can see the salary of Alex who is in his hierarchy
        Employee employee = fetch(client, "4");
        assertEquals("Alex", employee.firstName());
        assertEquals("Johnson", employee.lastName());
        assertEquals(new BigDecimal("115000"), employee.salary());

        // Marvin cannot see the salary of Morgan who is not in his hierarchy
        employee = fetch(client, "7");
        assertEquals("Morgan", employee.firstName());
        assertEquals("Lee", employee.lastName());
        assertNull(employee.salary());
    }

    private Employee fetch(BlockingHttpClient client, String employeeId) {
        HttpRequest<?> request = HttpRequest.GET(UriBuilder.of("/employee")
                .path(employeeId)
                .build());

        HttpResponse<@NotNull Employee> response = assertDoesNotThrow(() -> client.exchange(request, Employee.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        return assertDoesNotThrow(() -> response.getBody().orElseThrow());
    }

    @Requires(property = "spec.name", value = "EmployeeControllerTest")
    @Singleton
    static class MarvinAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            return Publishers.just(Authentication.build("MARVIN"));
        }
    }

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Oracle.getProperties();
    }
}
