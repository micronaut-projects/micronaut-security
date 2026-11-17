package io.micronaut.security.token.paseto.generator

import dev.paseto.jpaseto.Version
import dev.paseto.jpaseto.lang.Keys
import io.micronaut.security.token.paseto.config.PrivateKeyConfiguration
import io.micronaut.security.token.paseto.config.VersionedSharedSecretConfiguration
import spock.lang.Specification

import javax.crypto.SecretKey
import java.security.PrivateKey

class PasetoBuilderGeneratorSpec extends Specification {

    void "local builder generator creates builders for supported versions"() {
        expect:
        new LocalPasetoBuilderGenerator(sharedSecretConfiguration(Version.V1)).builder()
        new LocalPasetoBuilderGenerator(sharedSecretConfiguration(Version.V2)).builder()
    }

    void "public builder generator creates builders for supported versions"() {
        expect:
        new PublicPasetoBuilderGenerator(privateKeyConfiguration(Version.V1)).builder()
        new PublicPasetoBuilderGenerator(privateKeyConfiguration(Version.V2)).builder()
    }

    private static VersionedSharedSecretConfiguration sharedSecretConfiguration(Version version) {
        new VersionedSharedSecretConfiguration() {
            @Override
            Version getVersion() {
                version
            }

            @Override
            SecretKey getSharedSecret() {
                Keys.secretKey()
            }
        }
    }

    private static PrivateKeyConfiguration privateKeyConfiguration(Version version) {
        new PrivateKeyConfiguration() {
            @Override
            Version getVersion() {
                version
            }

            @Override
            PrivateKey getPrivateKey() {
                Keys.keyPairFor(version).private
            }
        }
    }
}
