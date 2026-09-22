package io.micronaut.security.csrf.filter;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.web.router.RouteAttributes;
import io.micronaut.web.router.UriRouteMatch;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@link io.micronaut.web.router.RouteMatch} stored in the request is owned by the request and is still needed to execute the route.
 * {@link CsrfFilter} must therefore never close it.
 */
class CsrfFilterRouteMatchNotClosedTest {

    @Test
    void uriMatchCheckDoesNotCloseTheRouteMatch() {
        CsrfFilter filter = csrfFilter();

        AtomicInteger matchingCloseCalls = new AtomicInteger();
        HttpRequest<?> matchingRequest = HttpRequest.POST("/password/change", "");
        RouteAttributes.setRouteMatch(matchingRequest, uriRouteMatch("/password/change", matchingCloseCalls));
        assertTrue(filter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(matchingRequest));
        assertEquals(0, matchingCloseCalls.get());

        AtomicInteger nonMatchingCloseCalls = new AtomicInteger();
        HttpRequest<?> nonMatchingRequest = HttpRequest.POST("/assets/app.css", "");
        RouteAttributes.setRouteMatch(nonMatchingRequest, uriRouteMatch("/assets/app.css", nonMatchingCloseCalls));
        assertFalse(filter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch(nonMatchingRequest));
        assertEquals(0, nonMatchingCloseCalls.get());
    }

    @Test
    void filterDoesNotCloseTheRouteMatch() throws Exception {
        CsrfFilter filter = csrfFilter();
        AtomicInteger closeCalls = new AtomicInteger();
        HttpRequest<?> request = HttpRequest.GET("/password/change");
        RouteAttributes.setRouteMatch(request, uriRouteMatch("/password/change", closeCalls));
        assertNull(filter.csrfFilter(request).get());
        assertEquals(0, closeCalls.get());
    }

    private static CsrfFilter csrfFilter() {
        CsrfFilterConfiguration configuration = new CsrfFilterConfiguration() {
            @Override
            public String getRegexPattern() {
                return "^(?!/assets/).*$";
            }

            @Override
            public Set<HttpMethod> getMethods() {
                return Set.of(HttpMethod.POST);
            }

            @Override
            public Set<MediaType> getContentTypes() {
                return Set.of(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
            }
        };
        return new CsrfFilter(configuration, Collections.emptyList(), Collections.emptyList(), (request, token) -> false, null);
    }

    private static UriRouteMatch<?, ?> uriRouteMatch(String uri, AtomicInteger closeCalls) {
        return (UriRouteMatch<?, ?>) Proxy.newProxyInstance(
                CsrfFilterRouteMatchNotClosedTest.class.getClassLoader(),
                new Class<?>[]{UriRouteMatch.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "close" -> {
                        closeCalls.incrementAndGet();
                        yield null;
                    }
                    case "getUri" -> uri;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "StubUriRouteMatch[" + uri + "]";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
