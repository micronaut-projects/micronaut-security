package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig
import com.unboundid.ldap.listener.InMemoryListenerConfig
import com.unboundid.ldif.LDIFReader
import com.unboundid.util.ssl.SSLUtil
import io.micronaut.core.io.ResourceResolver
import io.micronaut.http.HttpVersion
import io.micronaut.http.ssl.SslBuilder
import io.micronaut.http.ssl.SslConfiguration
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import reactor.core.publisher.Flux
import spock.lang.Specification

import javax.net.ssl.TrustManagerFactory

abstract class InMemoryLdapSpec extends Specification {

    InMemoryDirectoryServer createServer(String ldifPath, boolean ssl = false) {
        InMemoryDirectoryServerConfig config =
                new InMemoryDirectoryServerConfig("dc=example,dc=com")
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password")

        if (ssl) {
            SslConfiguration sslConfiguration = new SslConfiguration()
            sslConfiguration.getKeyStore().setPath("classpath:keystore.p12")
            sslConfiguration.getKeyStore().setPassword("foobar")
            sslConfiguration.getKeyStore().setType("PKCS12")
            sslConfiguration.setCiphers(["TLS_DH_anon_WITH_AES_128_CBC_SHA"] as String[])

            def builder = new SslBuilder<Object>(new ResourceResolver()) {
                TrustManagerFactory getTrust() {
                    getTrustManagerFactory(sslConfiguration)
                }

                @Override
                Optional<Object> build(SslConfiguration sslConfig, HttpVersion version) {
                    return null
                }

                @Override
                Optional<Object> build(SslConfiguration sslConfig) {
                    return null
                }
            }
            SSLUtil serverSSLUtil = new SSLUtil(builder.getTrust().getTrustManagers())
            serverSSLUtil.setDefaultSSLProtocol("TLS")
            config.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS", 0,
                    serverSSLUtil.createSSLServerSocketFactory()))
        }

        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config)
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(ldifPath)
        ds.importFromLDIF(true, new LDIFReader(inputStream))
        ds
    }

    AuthenticationRequest createAuthenticationRequest(String username, String password) {
        new AuthenticationRequest() {
            @Override
            Object getIdentity() {
                return username
            }

            @Override
            Object getSecret() {
                return password
            }
        }
    }

    AuthenticationResponse authenticate(LdapAuthenticationProvider authenticationProvider, String username, String password = "password") {
        Flux.from(authenticationProvider.authenticate(null, createAuthenticationRequest(username, password)))
                .onErrorResume(t -> {
                        return Flux.just(((AuthenticationException) t).getResponse())
                })
                .blockFirst()
    }

}
