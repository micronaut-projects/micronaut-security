package io.micronaut.security.oauth2.grants;

import java.util.HashMap;

public class SecureGrantMap extends HashMap<String, String> implements SecureGrant {

    public SecureGrantMap(int initialCapacity) {
        super(initialCapacity);
    }

    public SecureGrantMap() {
        super();
    }

    @Override
    public void setClientId(String clientId) {
        put("client_id", clientId);
    }

    @Override
    public void setClientSecret(String clientSecret) {
        put("client_secret", clientSecret);
    }
}
