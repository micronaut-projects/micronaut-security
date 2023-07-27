package io.micronaut.security.token.jwt.signature.jwks.redis;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;

public interface RedisJwksClient {

    JWKSet get(String url);

    boolean isPresent(String url);
    void clear(String url);

    List<String> getKeyIds(String url);

    void setJWKSet(String url, JWKSet jwkSet);

}
