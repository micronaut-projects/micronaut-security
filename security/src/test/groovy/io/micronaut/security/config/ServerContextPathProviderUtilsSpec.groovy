package io.micronaut.security.config

import io.micronaut.http.context.ServerContextPathProvider
import spock.lang.Specification
import spock.lang.Unroll

class ServerContextPathProviderUtilsSpec extends Specification {

    @Unroll("for url #url and server context path: #path expect => #expected")
    void "Test ServerContextPathProviderUtils::prependContextPath"(String expected, String url, ServerContextPathProvider serverContextPathProvider, String path) {
        expect:

        expected ==  ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)
        where:
        expected     | url     | serverContextPathProvider
        '/book'      | '/book' | () -> null
        '/book'      | '/book' | () -> '/'
        '/app/book'  | '/book' | () -> '/app'
        '/app/book'  | '/book' | () -> 'app'
        path = serverContextPathProvider.contextPath
    }
}
