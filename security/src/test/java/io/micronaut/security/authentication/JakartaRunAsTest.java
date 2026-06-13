package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.utils.SecurityService;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.annotation.security.RunAs;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "JakartaRunAsTest")
@MicronautTest
class JakartaRunAsTest {

    @Test
    void verifyYouCanUserTheJakartaRunAsToAddARole(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        SalaryAggregates aggregates = client.retrieve(
            HttpRequest.GET("/salary").basicAuth("sdelamo", "ilikepotatoes"),
            SalaryAggregates.class
        );
        SalaryAggregates expected = new SalaryAggregates(new BigDecimal("6900"), new BigDecimal("13000"), new BigDecimal("9826.00"), 5L);
        assertEquals(expected, aggregates);
    }

    @Requires(property = "spec.name", value = "JakartaRunAsTest")
    @Singleton
    static class RunAsProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                            @NonNull AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success(
                "sdelamo",
                List.of("ROLE_USER", "ROLE_ADMIN"));
        }
    }

    @Requires(property = "spec.name", value = "JakartaRunAsTest")
    @Controller("/salary")
    static class SalaryAggregatesController {
        private final SalaryAggregatesService salaryAggregatesService;

        SalaryAggregatesController(SalaryAggregatesService salaryAggregatesService) {
            this.salaryAggregatesService = salaryAggregatesService;
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        SalaryAggregates index() {
            return salaryAggregatesService.getSalaryAggregates();
        }
    }

    @Requires(property = "spec.name", value = "JakartaRunAsTest")
    @RunAs("ORACLE_DATA_ROLE_COMPENSATION_ANALYST")
    @Singleton
    static class SalaryAggregatesService {
        private final SecurityService securityService;

        SalaryAggregatesService(SecurityService securityService) {
            this.securityService = securityService;
        }

        SalaryAggregates getSalaryAggregates() {
            if (securityService.getAuthentication().map(Authentication::getRoles).orElse(Collections.emptyList()).contains("ORACLE_DATA_ROLE_COMPENSATION_ANALYST")) {
                return new SalaryAggregates(new BigDecimal("6900"), new BigDecimal("13000"), new BigDecimal("9826.00"), 5L);
            }
            return new SalaryAggregates(new BigDecimal("82000"), new BigDecimal("82000"), new BigDecimal("82000"), 1L);
        }
    }

    @Introspected
    record SalaryAggregates(
        BigDecimal min,
        BigDecimal max,
        BigDecimal sum,
        Long count) {
    }
}
