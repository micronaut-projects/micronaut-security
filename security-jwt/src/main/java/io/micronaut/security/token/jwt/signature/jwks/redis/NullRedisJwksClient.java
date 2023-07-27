package io.micronaut.security.token.jwt.signature.jwks.redis;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;

public class NullRedisJwksClient implements  RedisJwksClient {

    @Override
    public JWKSet get(String url) {
        return null;
    }

    @Override
    public boolean isPresent(String url) {
        return false;
    }

    @Override
    public void clear(String url) {

    }

    @Override
    public List<String> getKeyIds(String url) {
        return null;
    }

    @Override
    public void setJWKSet(String url,JWKSet jwkSet) {

    }
}
