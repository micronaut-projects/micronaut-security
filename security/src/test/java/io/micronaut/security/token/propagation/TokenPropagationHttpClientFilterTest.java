package io.micronaut.security.token.propagation;

import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.context.ServerHttpRequestContext;
import io.micronaut.http.util.OutgoingHttpRequestProcessorImpl;
import io.micronaut.security.filters.SecurityFilter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenPropagationHttpClientFilterTest {

    private static final String PROPAGATED_TOKEN = "propagated";

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "Bearer  | Bearer existing",
        "Bearer  | bearer existing",
        "Bearer  | BEARER existing",
        "'Bearer ' | Bearer existing",
    })
    void anExistingTokenHeaderIsNotOverwritten(String prefix, String existing) {
        MutableHttpRequest<?> target = HttpRequest.GET("/").header(HttpHeaders.AUTHORIZATION, existing);

        filter(prefix, target);

        assertEquals(List.of(existing), target.getHeaders().getAll(HttpHeaders.AUTHORIZATION));
    }

    @Test
    void theTokenIsWrittenWhenTheHeaderHasADifferentScheme() {
        MutableHttpRequest<?> target = HttpRequest.GET("/").header(HttpHeaders.AUTHORIZATION, "Basic abc");

        filter("Bearer", target);

        assertEquals(List.of("Basic abc", "Bearer " + PROPAGATED_TOKEN), target.getHeaders().getAll(HttpHeaders.AUTHORIZATION));
    }

    @Test
    void theTokenIsWrittenWhenTheRequestHasNoTokenHeader() {
        MutableHttpRequest<?> target = HttpRequest.GET("/");

        filter("Bearer", target);

        assertEquals(List.of("Bearer " + PROPAGATED_TOKEN), target.getHeaders().getAll(HttpHeaders.AUTHORIZATION));
    }

    private static void filter(String prefix, MutableHttpRequest<?> target) {
        HttpHeaderTokenPropagatorConfigurationProperties propagatorConfiguration = new HttpHeaderTokenPropagatorConfigurationProperties();
        propagatorConfiguration.setPrefix(prefix);
        TokenPropagationConfigurationProperties configuration = new TokenPropagationConfigurationProperties();
        configuration.setUriRegex("/.*");
        TokenPropagationHttpClientFilter filter = new TokenPropagationHttpClientFilter(configuration,
            new OutgoingHttpRequestProcessorImpl(),
            new HttpHeaderTokenPropagator(propagatorConfiguration));
        MutableHttpRequest<Object> currentRequest = HttpRequest.GET("/");
        currentRequest.setAttribute(SecurityFilter.TOKEN, PROPAGATED_TOKEN);
        try (PropagatedContext.Scope ignored = PropagatedContext.getOrEmpty().plus(new ServerHttpRequestContext(currentRequest)).propagate()) {
            filter.doFilter(target);
        }
    }
}
