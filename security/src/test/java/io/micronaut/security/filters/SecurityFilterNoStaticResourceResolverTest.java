package io.micronaut.security.filters;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.web.router.resource.StaticResourceResolver;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A {@link SecurityFilter} without a {@link StaticResourceResolver} cannot tell whether the server would serve an
 * unmatched request as a static resource, so it must reject it even when {@code reject-not-found} is disabled.
 */
class SecurityFilterNoStaticResourceResolverTest {

    @Test
    void nullStaticResourceResolverFailsClosedWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled(), null);
        assertRejected(filter);
    }

    @Test
    @SuppressWarnings("deprecation")
    void deprecatedThreeArgumentConstructorFailsClosedWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled());
        assertRejected(filter);
    }

    @Test
    void unmatchedRequestProceedsWithResolverWhenRejectNotFoundIsDisabled() {
        SecurityFilter filter = new SecurityFilter(Collections.emptyList(), Collections.emptyList(),
            rejectNotFoundDisabled(), StaticResourceResolver.EMPTY);
        RecordingChain chain = new RecordingChain();
        HttpRequest<?> request = HttpRequest.GET("/exports/protected.txt");

        MutableHttpResponse<?> response = Mono.from(filter.doFilter(request, chain)).block();

        assertEquals(HttpStatus.OK, response.status());
        assertEquals(Collections.singletonList(request), chain.proceeded);
    }

    private static void assertRejected(SecurityFilter filter) {
        RecordingChain chain = new RecordingChain();
        HttpRequest<?> request = HttpRequest.GET("/exports/protected.txt");

        assertThrows(AuthorizationException.class, () -> Mono.from(filter.doFilter(request, chain)).block());
        assertTrue(chain.proceeded.isEmpty());
    }

    private static SecurityConfiguration rejectNotFoundDisabled() {
        return new SecurityConfiguration() {
            @Override
            public List<String> getIpPatterns() {
                return Collections.emptyList();
            }

            @Override
            public List<InterceptUrlMapPattern> getInterceptUrlMap() {
                return Collections.emptyList();
            }

            @Override
            public AuthenticationMode getAuthentication() {
                return null;
            }

            @Override
            public boolean isRejectNotFound() {
                return false;
            }
        };
    }

    private static final class RecordingChain implements ServerFilterChain {
        private final List<HttpRequest<?>> proceeded = new ArrayList<>();

        @Override
        public Publisher<MutableHttpResponse<?>> proceed(HttpRequest<?> request) {
            proceeded.add(request);
            return Mono.just(HttpResponse.ok());
        }
    }
}
