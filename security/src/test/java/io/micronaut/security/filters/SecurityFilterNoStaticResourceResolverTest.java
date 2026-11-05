package io.micronaut.security.filters;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.web.router.resource.StaticResourceResolver;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A filter created with a deprecated constructor has no {@link StaticResourceResolver} and cannot tell whether the
 * server would serve an unmatched request as a static resource. With {@code micronaut.security.reject-not-found=false}
 * it must fail closed instead of letting such requests through.
 */
class SecurityFilterNoStaticResourceResolverTest {

    @Test
    @SuppressWarnings("removal")
    void deprecatedFiveArgumentConstructorFailsClosedWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled(), mock(SecurityFilterConfiguration.class), null);
        assertRejected(filter);
    }

    @Test
    @SuppressWarnings("removal")
    void deprecatedThreeArgumentConstructorFailsClosedWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled());
        assertRejected(filter);
    }

    @Test
    void unmatchedRequestProceedsWithResolverWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled(), mock(SecurityFilterConfiguration.class), null, StaticResourceResolver.EMPTY);
        ServerFilterChain chain = chain();
        HttpRequest<?> request = HttpRequest.GET("/exports/protected.txt");

        MutableHttpResponse<?> response = Mono.from(filter.doFilter(request, chain)).block();

        assertEquals(HttpStatus.OK, response.status());
        verify(chain).proceed(request);
    }

    private static void assertRejected(SecurityFilter filter) {
        ServerFilterChain chain = chain();
        HttpRequest<?> request = HttpRequest.GET("/exports/protected.txt");

        assertThrows(AuthorizationException.class, () -> Mono.from(filter.doFilter(request, chain)).block());
        verify(chain, never()).proceed(any());
    }

    private static SecurityConfiguration rejectNotFoundDisabled() {
        SecurityConfiguration securityConfiguration = mock(SecurityConfiguration.class);
        when(securityConfiguration.isRejectNotFound()).thenReturn(false);
        return securityConfiguration;
    }

    private static ServerFilterChain chain() {
        ServerFilterChain chain = mock(ServerFilterChain.class);
        Publisher<MutableHttpResponse<?>> ok = Mono.just(HttpResponse.ok());
        when(chain.proceed(any())).thenReturn(ok);
        return chain;
    }
}
