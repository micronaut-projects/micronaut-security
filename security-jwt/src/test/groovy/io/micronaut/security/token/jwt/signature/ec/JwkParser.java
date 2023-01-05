package io.micronaut.security.token.jwt.signature.ec;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.text.ParseException;

public class JwkParser {

    protected ECKey parseECKey(String jsonJwk) throws ParseException {
        JWK jwk = JWK.parse(jsonJwk);
        if (!(jwk instanceof ECKey)) {
            throw new ParseException("jwk provided isn't ECKey", 0);
        }
        return (ECKey) jwk;
    }
}
