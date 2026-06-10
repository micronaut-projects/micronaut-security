package io.micronaut.docs.claimsjti;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.claims.JtiGenerator;
import jakarta.inject.Singleton;

import java.util.UUID;

@Requires(property = "spec.name", value = "claims-generation-docs")
//tag::clazz[]
@Singleton
class CustomJtiGenerator implements JtiGenerator {

    @Override
    public String generateJtiClaim() {
        return UUID.randomUUID().toString();
    }
}
//end::clazz[]
