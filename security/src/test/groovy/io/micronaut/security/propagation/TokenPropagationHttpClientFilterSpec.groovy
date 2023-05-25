package io.micronaut.security.propagation

import io.micronaut.core.propagation.PropagatedContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.context.ServerHttpRequestContext
import io.micronaut.http.util.OutgoingHttpRequestProcessor
import io.micronaut.http.util.OutgoingHttpRequestProcessorImpl
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.token.propagation.TokenPropagationConfigurationProperties
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter
import io.micronaut.security.token.propagation.TokenPropagator
import spock.lang.Shared
import spock.lang.Specification

import java.util.regex.Pattern

class TokenPropagationHttpClientFilterSpec extends Specification {

    @Shared
    OutgoingHttpRequestProcessor requestProcessor = new OutgoingHttpRequestProcessorImpl()

    void "if current request attribute TOKEN contains a token, it gets written to target request"() {
        given:
        String sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        TokenPropagator tokenPropagator = Mock(TokenPropagator) {
            1 * findToken(_) >> Optional.empty()
        }
        TokenPropagationConfigurationProperties config = new TokenPropagationConfigurationProperties()
        config.setUriRegex("/.*")
        TokenPropagationHttpClientFilter clientFilter = new TokenPropagationHttpClientFilter(config, requestProcessor, tokenPropagator)
        MutableHttpRequest<?> targetRequest = Stub(MutableHttpRequest) {
            getUri() >> URI.create("/")
        }
        HttpRequest<Object> currentRequest =  Stub(MutableHttpRequest) {
            getAttribute(SecurityFilter.TOKEN, String.class) >> Optional.of(sampleJwt)
        }
        ServerHttpRequestContext
        when:
        try (PropagatedContext.Scope ignore = PropagatedContext.getOrEmpty()
                .plus(new ServerHttpRequestContext(currentRequest))
                .propagate()) {
            clientFilter.doFilter(targetRequest)
        }
        then:
        1 * tokenPropagator.writeToken(targetRequest, sampleJwt)
    }

    void "if current request attribute TOKEN does NOT contains a token, it is not written to target request, but request proceeds"() {
        given:
        TokenPropagator tokenPropagator = Mock(TokenPropagator) {
            findToken(_) >> Optional.empty()
        }
        TokenPropagationConfigurationProperties config = new TokenPropagationConfigurationProperties()
        TokenPropagationHttpClientFilter clientFilter = new TokenPropagationHttpClientFilter(config, requestProcessor, tokenPropagator)
        MutableHttpRequest<?> targetRequest = Stub(MutableHttpRequest) {
            getUri() >> URI.create("/")
        }
        HttpRequest<Object> currentRequest =  Stub(MutableHttpRequest) {
            getAttribute(SecurityFilter.TOKEN) >> Optional.empty()
        }

        when:
        try (PropagatedContext.Scope ignore = PropagatedContext.getOrEmpty()
                .plus(new ServerHttpRequestContext(currentRequest))
                .propagate()) {
            clientFilter.doFilter(targetRequest)
        }

        then:
        0 * tokenPropagator.writeToken(targetRequest, _)
    }

    void "if target request contains a token, it does not overwrite it"() {
        String sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        TokenPropagator tokenPropagator = Mock(TokenPropagator) {
            findToken(_) >> Optional.of(sampleJwt)
        }
        TokenPropagationConfigurationProperties config = new TokenPropagationConfigurationProperties()
        TokenPropagationHttpClientFilter clientFilter = new TokenPropagationHttpClientFilter(config, requestProcessor, tokenPropagator)
        MutableHttpRequest<?> targetRequest = Stub(MutableHttpRequest) {
            getAttribute(SecurityFilter.TOKEN) >> Optional.of(sampleJwt)
        }

        HttpRequest<Object> currentRequest =  Stub(MutableHttpRequest) {
            getAttribute(SecurityFilter.TOKEN) >> Optional.of(sampleJwt)
        }

        when:
        try (PropagatedContext.Scope ignore = PropagatedContext.getOrEmpty()
                .plus(new ServerHttpRequestContext(currentRequest))
                .propagate()) {
            clientFilter.doFilter(targetRequest)
        }

        then:
        0 * tokenPropagator.writeToken(targetRequest, sampleJwt)
    }
}
