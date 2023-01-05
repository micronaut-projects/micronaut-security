package io.micronaut.security.token.jwt.signature.ec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

public class TestECSignatureGeneratorConfiguration extends JwkParser implements ECSignatureGeneratorConfiguration {

    private final ECPrivateKey privateKey;

    private final ECPublicKey publicKey;

    private final JWSAlgorithm jwsAlgorithm;

    TestECSignatureGeneratorConfiguration(String jsonJwk) throws ParseException, JOSEException {
        ECKey ecKey = parseECKey(jsonJwk);
        this.privateKey = ecKey.toECPrivateKey();
        this.publicKey = ecKey.toECPublicKey();
        this.jwsAlgorithm = new JWSAlgorithm(ecKey.getAlgorithm().getName());
    }

    @Override
    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public JWSAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm;
    }

    @Override
    public ECPrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
