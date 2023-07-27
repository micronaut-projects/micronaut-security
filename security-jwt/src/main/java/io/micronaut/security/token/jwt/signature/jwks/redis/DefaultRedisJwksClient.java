package io.micronaut.security.token.jwt.signature.jwks.redis;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.inject.Singleton;
import java.util.List;
import redis.clients.jedis.JedisCluster;

public class DefaultRedisJwksClient implements RedisJwksClient {
    private JedisCluster jedisCluster;
    public DefaultRedisJwksClient(JedisCluster jedisCluster) {
        this.jedisCluster = jedisCluster;
    }

    public JWKSet get(String url) {
        return jedisCluster.jsonGet(url, JWKSet.class);
    }

    public boolean isPresent(String url) {
        return jedisCluster.jsonGet(url , JWKSet.class) != null;
    }
    public void clear(String url)  {
        jedisCluster.jsonClear(url);
    }

    public List<String> getKeyIds(String url) {
        return jedisCluster.jsonGet(url, JWKSet.class).getKeys().stream().map(JWK::getKeyID).toList();
    }

    @Override
    public void setJWKSet(String url, JWKSet jwkSet) {
        jedisCluster.jsonSet(url, jwkSet);
    }
}
