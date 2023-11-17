package io.micronaut.security.token.reader
import spock.lang.Specification

class TokenResolverSpec extends Specification {

    void "TokenResolver resolveTokens has a default implementation"() {
        given:
        TokenResolver tokenResolver = new CustomTokenResolver()

        expect:
        tokenResolver.resolveToken(null).isPresent()
        "customToken" == tokenResolver.resolveToken(null).get()
        ["customToken"] == tokenResolver.resolveTokens(null)
    }

    static class CustomTokenResolver<T> implements TokenResolver<T> {

        @Override
        @Deprecated
        Optional<String> resolveToken(T request) {
            return Optional.of("customToken")
        }


    }
}
