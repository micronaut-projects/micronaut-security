package io.micronaut.security.token.paseto.converters

import dev.paseto.jpaseto.Purpose
import dev.paseto.jpaseto.Version
import dev.paseto.jpaseto.lang.Keys
import io.micronaut.core.convert.ConversionContext
import spock.lang.Specification

class PasetoConvertersSpec extends Specification {

    void "purpose converter converts valid values and ignores invalid values"() {
        given:
        PurposeConveter converter = new PurposeConveter()

        expect:
        converter.convert('local', Purpose, ConversionContext.DEFAULT).get() == Purpose.LOCAL
        converter.convert('public', Purpose, ConversionContext.DEFAULT).get() == Purpose.PUBLIC
        converter.convert('invalid', Purpose, ConversionContext.DEFAULT).isEmpty()
        converter.convert(null, Purpose, ConversionContext.DEFAULT).isEmpty()
    }

    void "version converter converts valid values and ignores invalid values"() {
        given:
        VersionConverter converter = new VersionConverter()

        expect:
        converter.convert('v1', Version, ConversionContext.DEFAULT).get() == Version.V1
        converter.convert('v2', Version, ConversionContext.DEFAULT).get() == Version.V2
        converter.convert('v3', Version, ConversionContext.DEFAULT).isEmpty()
        converter.convert(null, Version, ConversionContext.DEFAULT).isEmpty()
    }

    void "secret key converter decodes base64 encoded keys"() {
        given:
        SecretKeyConverter converter = new SecretKeyConverter()
        String encoded = Base64.encoder.encodeToString(Keys.secretKey().encoded)

        expect:
        converter.convert(encoded, javax.crypto.SecretKey, ConversionContext.DEFAULT).get().encoded == Base64.decoder.decode(encoded)
        converter.convert(null, javax.crypto.SecretKey, ConversionContext.DEFAULT).isEmpty()
    }
}
