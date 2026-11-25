package io.micronaut.security.ldap;

import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;

/**
 * Test-only JNDI socket factory that trusts the self-signed certificate of the in-memory LDAPS server.
 * JNDI instantiates it through the {@code java.naming.ldap.factory.socket} environment property, which
 * requires a public class with a static {@code getDefault()} method.
 */
public final class TrustAllSslSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory delegate;

    private TrustAllSslSocketFactory() {
        try {
            this.delegate = new SSLUtil(new TrustAllTrustManager()).createSSLSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static SocketFactory getDefault() {
        return new TrustAllSslSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return delegate.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return delegate.createSocket(address, port, localAddress, localPort);
    }
}
