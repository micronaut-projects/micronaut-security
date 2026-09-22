# tag::clazz[]
from jakarta.inject import Named
from micronaut.context.annotation import Bean, Factory, Requires
from micronaut.security.token.jwt.signature import SignatureGeneratorConfiguration
from micronaut.security.token.jwt.signature.rsa import RSASignatureGenerator, RSASignatureGeneratorConfiguration
# end::clazz[]


@Requires(property="spec.name", value="RSASignatureGeneratorTest")
# tag::clazz[]

@Factory
class MySignatureGeneratorConfigurationFactory:

    @Bean
    @Named("generator")  # <1>
    def signature_generator_configuration(self, configuration: RSASignatureGeneratorConfiguration) -> SignatureGeneratorConfiguration:  # <2>
        return RSASignatureGenerator(configuration)
# end::clazz[]
