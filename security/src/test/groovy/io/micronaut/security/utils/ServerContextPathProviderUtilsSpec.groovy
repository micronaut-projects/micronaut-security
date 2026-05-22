package io.micronaut.security.utils

import io.micronaut.http.context.ServerContextPathProvider
import io.micronaut.security.config.ServerContextPathProviderUtils
import spock.lang.Specification

class ServerContextPathProviderUtilsSpec extends Specification {

    void "returns original URL if it is absolute"() {
        given:
        String url = "http://example.com:8080/web"
        ServerContextPathProvider serverContextPathProvider = Mock(ServerContextPathProvider)

        when:
        String result = ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)

        then:
        result == url
    }

    void "prepends context path to a relative URL"() {
        given:
        String url = "/relative"
        ServerContextPathProvider serverContextPathProvider = Mock(ServerContextPathProvider) {
            getContextPath() >> "/context-path"
        }

        when:
        String result = ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)

        then:
        result == "/context-path/relative"
    }

    void "handles URL with query parameters and fragments"() {
        given:
        String url = "/relative?query=param#fragment"
        ServerContextPathProvider serverContextPathProvider = Mock(ServerContextPathProvider) {
            getContextPath() >> "/context-path"
        }

        when:
        String result = ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)

        then:
        result == "/context-path/relative?query=param#fragment"
    }

    void "handles empty string as URL input"() {
        given:
        String url = ""
        ServerContextPathProvider serverContextPathProvider = Mock(ServerContextPathProvider) {
            getContextPath() >> "/context"
        }

        when:
        String result = ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)

        then:
        result == "/context"
    }

    void "manages null context path from ServerContextPathProvider"() {
        given:
        String url = "relative/path"
        ServerContextPathProvider serverContextPathProvider = Mock(ServerContextPathProvider) {
            getContextPath() >> null
        }

        when:
        String result = ServerContextPathProviderUtils.prependContextPath(url, serverContextPathProvider)

        then:
        result == url
    }

}
