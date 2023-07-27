package io.micronaut.security.token.jwt.signature.jwks.redis;

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisCluster;

@Factory
public class RedisJwksClientFactory {

    private final RedisConfiguration redisConfiguration;

    public RedisJwksClientFactory(RedisConfiguration redisConfiguration) {
        this.redisConfiguration = redisConfiguration;
    }

    @Bean
    public RedisJwksClient getRedisJwksClient() {
        if (redisConfiguration.isEnabled()) {
            HostAndPort hostAndPort = new HostAndPort(redisConfiguration.getRedisHost(),
                redisConfiguration.getRedisPort());
            JedisCluster jedisCluster = new JedisCluster(hostAndPort);
            return new DefaultRedisJwksClient(jedisCluster);
        }
        return new NullRedisJwksClient();
    }

}
