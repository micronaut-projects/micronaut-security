package io.micronaut.security.x509

import io.micronaut.security.filters.AuthenticationFetcher
import io.micronaut.security.token.TokenAuthenticationFetcher;

class X509AuthenticationFetcherOrderSpec extends AbstractX509Spec {

    void "X509AuthenticationFetcher is ordered before TokenAuthenticationFetcher"() {
        when:
        List<AuthenticationFetcher> authenticationFetchers = applicationContext.getBeansOfType(AuthenticationFetcher)
        int x509Index = authenticationFetchers.findIndexOf {it instanceof X509AuthenticationFetcher }
        int tokenIndex =authenticationFetchers.findIndexOf {it instanceof TokenAuthenticationFetcher }

        then:
        x509Index != -1
        tokenIndex != -1
        x509Index < tokenIndex
    }
}
