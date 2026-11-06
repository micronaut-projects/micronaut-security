package io.micronaut.security.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.web.router.resource.StaticResourceResolver;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultStaticResourceMatcherTest {

    @Test
    void theMatcherIsTheDefaultBeanWhenTheRouterIsPresent() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            assertInstanceOf(DefaultStaticResourceMatcher.class, ctx.getBean(StaticResourceMatcher.class));
        }
    }

    @Test
    void aRequestWhoseDecodedPathResolvesIsAStaticResource() throws MalformedURLException {
        StaticResourceResolver resolver = resolver("/exports/protected.txt");

        assertTrue(new DefaultStaticResourceMatcher(resolver).isStaticResource(HttpRequest.GET("/exports/protected.txt")));
        verify(resolver, times(1)).resolve(anyString());
    }

    @Test
    void aRequestWhoseRawPathResolvesIsAStaticResource() throws MalformedURLException {
        StaticResourceResolver resolver = resolver("/exports/protected%2Etxt");

        assertTrue(new DefaultStaticResourceMatcher(resolver).isStaticResource(HttpRequest.GET("/exports/protected%2Etxt")));
        verify(resolver).resolve("/exports/protected.txt");
        verify(resolver).resolve("/exports/protected%2Etxt");
    }

    @Test
    void aRequestNeitherFormOfWhichResolvesIsNotAStaticResource() throws MalformedURLException {
        StaticResourceResolver resolver = resolver("/exports/other.txt");

        assertFalse(new DefaultStaticResourceMatcher(resolver).isStaticResource(HttpRequest.GET("/exports/protected.txt")));
        verify(resolver, times(1)).resolve(anyString());
        verify(resolver, never()).resolve("/exports/other.txt");
    }

    private static StaticResourceResolver resolver(String servedPath) throws MalformedURLException {
        StaticResourceResolver resolver = mock(StaticResourceResolver.class);
        when(resolver.resolve(anyString())).thenReturn(Optional.empty());
        when(resolver.resolve(servedPath)).thenReturn(Optional.of(URI.create("file:///tmp/exports/protected.txt").toURL()));
        return resolver;
    }
}
