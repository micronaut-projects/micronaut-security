package io.micronaut.security.docs.jwtgeneratorrsa

//tag::clazz[]
import io.micronaut.context.annotation.Bean
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Requires
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
//end::clazz[]

@Requires(property = "spec.name", value = "RSASignatureGeneratorTest")
//tag::clazz[]

@Factory
class MySignatureGeneratorConfigurationFactory {

    @Bean
    @Named("generator") // <1>
    SignatureGeneratorConfiguration signatureGeneratorConfiguration(RSASignatureGeneratorConfiguration configuration) { // <2>
        new RSASignatureGenerator(configuration)
    }
}
//end::clazz[]
