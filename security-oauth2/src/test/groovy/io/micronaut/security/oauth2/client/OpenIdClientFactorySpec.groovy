package io.micronaut.security.oauth2.client

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import jakarta.annotation.security.PermitAll
import org.slf4j.LoggerFactory
import spock.lang.Issue
import spock.lang.PendingFeature
import spock.lang.Specification

import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

class OpenIdClientFactorySpec extends Specification {

    void "starting an app does not call eagerly .well-known/openid-configuration"() {
        given:
        int authServerPort = SocketUtils.findAvailableTcpPort()
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.server.port': authServerPort,
                'spec.name': 'AuthServerOpenIdClientFactorySpec'
        ])
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                           : 'OpenIdClientFactorySpec',
                'micronaut.security.authentication'                   : 'cookie',
                'micronaut.security.oauth2.clients.okta.openid.issuer': "http://localhost:${authServerPort}/oauth2/default",
        ])

        when:
        OpenIdConfigurationController openIdConfigurationController = authServer.applicationContext.getBean(OpenIdConfigurationController)

        then:
        openIdConfigurationController.invocations == 0

        cleanup:
        authServer.close()
        server.close()
    }

    @Issue("https://github.com/micronaut-projects/micronaut-security/issues/604")
    @PendingFeature
    void "OpenID connect metadata fetching should not be done in netty event loop thread"() {
        given:
        MemoryAppender appender = new MemoryAppender()
        Logger fetcherlogger = (Logger) LoggerFactory.getLogger(DefaultOpenIdProviderMetadataFetcher.class)
        fetcherlogger.addAppender(appender)
        fetcherlogger.setLevel(Level.TRACE)
        Logger logger = (Logger) LoggerFactory.getLogger(HomeController.class)
        logger.addAppender(appender)
        logger.setLevel(Level.TRACE)
        appender.start()

        and: 'auth server'
        int authServerPort = SocketUtils.findAvailableTcpPort()
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.server.port': authServerPort,
                'spec.name':'AuthServerOpenIdClientFactorySpec'
        ])

        and: 'main app'
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'OpenIdClientFactorySpec',
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.oauth2.clients.okta.openid.issuer': "http://localhost:${authServerPort}/oauth2/default",
        ])

        when:
        server.applicationContext.createBean(HttpClient, server.URL).toBlocking().exchange(HttpRequest.GET("/"))

        then:
        appender.events.size() == 2
        1L == appender.events.stream().filter(threadName ->
                threadName.contains("EventLoop")).count()

        cleanup:
        authServer.close()
        server.close()
        appender.stop()
    }

    @Requires(property = 'spec.name', value = 'OpenIdClientFactorySpec')
    @Controller
    static class HomeController {
        private static final Logger LOG = LoggerFactory.getLogger(HomeController.class);

        DefaultOpenIdProviderMetadata metadata
        HomeController(DefaultOpenIdProviderMetadata metadata) {
            this.metadata = metadata
        }

        @PermitAll
        @Get
        @Status(HttpStatus.OK)
        void index() {
            LOG.info(Thread.currentThread().getName())
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdClientFactorySpec')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class OpenIdConfigurationController {
        int invocations = 0

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"https://dev-133320.okta.com/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final BlockingQueue<String> events = new LinkedBlockingQueue<>()

        @Override
        protected void append(ILoggingEvent e) {
            events.add(e.formattedMessage)
        }
    }
}
