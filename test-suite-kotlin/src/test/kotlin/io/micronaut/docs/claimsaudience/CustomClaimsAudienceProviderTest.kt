package io.micronaut.docs.claimsaudience

import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.Claims
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import io.micronaut.security.token.claims.ClaimsGenerator
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "claims-generation-docs")
@MicronautTest(startApplication = false)
class CustomClaimsAudienceProviderTest {

    @Inject
    lateinit var claimsAudienceProvider: ClaimsAudienceProvider

    @Inject
    lateinit var claimsGenerator: ClaimsGenerator

    @Test
    fun customClaimsAudienceProviderSuppliesJwtAudienceClaim() {
        val claims = claimsGenerator.generateClaims(Authentication.build("sherlock"), 3600)

        Assertions.assertEquals(listOf("https://api.example.com"), claimsAudienceProvider.audience())
        Assertions.assertEquals(listOf("https://api.example.com"), claims[Claims.AUDIENCE])
    }
}
