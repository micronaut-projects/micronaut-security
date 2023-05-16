package io.micronaut.security.x509

import io.micronaut.security.testutils.EmbeddedServerSpecification

abstract class AbstractX509Spec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.http.client.ssl.insecure-trust-all-certificates': 'true',
                'micronaut.http.client.ssl.key-store.password'          : 'secret',
                'micronaut.http.client.ssl.key-store.path'              : 'classpath:ssl/x509/client.p12',
                'micronaut.http.client.ssl.key-store.type'              : 'PKCS12',
                'micronaut.security.x509.enabled'                       : true,
                'micronaut.server.ssl.client-authentication'            : 'want',
                'micronaut.server.ssl.key-store.password'               : 'secret',
                'micronaut.server.ssl.key-store.path'                   : 'classpath:ssl/x509/keystore.p12',
                'micronaut.server.ssl.key-store.type'                   : 'PKCS12',
                'micronaut.server.ssl.trust-store.password'             : 'secret',
                'micronaut.server.ssl.trust-store.path'                 : 'classpath:ssl/x509/truststore.jks',
                'micronaut.server.ssl.trust-store.type'                 : 'JKS',
                'micronaut.server.ssl.build-self-signed'                       : false,
                'micronaut.ssl.enabled'                                 : true,
                'micronaut.server.ssl.port'                             : -1
        ]
    }
}
