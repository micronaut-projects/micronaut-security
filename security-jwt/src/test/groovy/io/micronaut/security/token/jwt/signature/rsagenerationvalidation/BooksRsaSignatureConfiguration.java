package io.micronaut.security.token.jwt.signature.rsagenerationvalidation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration;
import jakarta.inject.Named;

import java.security.interfaces.RSAPublicKey;

@Requires(property = "spec.name", value = "rsajwtbooks")
public class BooksRsaSignatureConfiguration implements RSASignatureConfiguration {

    private final RSAPublicKey rsaPublicKey;

    public BooksRsaSignatureConfiguration(RSAKey rsaJwk) {
        try {
            this.rsaPublicKey = rsaJwk.toRSAPublicKey();
        }  catch(JOSEException e) {
            throw new ConfigurationException("could not get the RSA Public Key");
        }
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return this.rsaPublicKey;
    }
}
