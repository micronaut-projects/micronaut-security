package io.micronaut.security.oauth2

trait ConfigurationFixture {
    Map<String, Object> getOauth2Config() {
        [
                "micronaut.security.enabled" : true,
                "micronaut.security.token.jwt.enabled" : true,
                'micronaut.security.oauth2.enabled' : true,
        ] as Map<String, Object>
    }
}
