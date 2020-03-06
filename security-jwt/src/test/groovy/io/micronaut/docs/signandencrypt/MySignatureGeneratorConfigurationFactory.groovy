package io.micronaut.docs.signandencrypt

import io.micronaut.context.annotation.Bean
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration

import javax.inject.Named

@Requires(notEnv = Environment.TEST)
//tag::clazz[]
@Factory
class MySignatureGeneratorConfigurationFactory {
    @Bean
    @Named("generator") // <1>
    SignatureGeneratorConfiguration signatureGeneratorConfiguration(RSASignatureGeneratorConfiguration configuration) {// <2>
        return new RSASignatureGenerator(configuration)
    }
}
//end::clazz[]
