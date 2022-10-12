package io.micronaut.security.session

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.cookie.Cookie
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.pages.HomePage
import io.micronaut.security.pages.LoginPage
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.security.utils.BaseUrlUtils
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared

class SessionAuthenticationSpec extends GebSpec implements YamlAsciidocTagCleaner {
    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Shared
    ApplicationContext applicationContext = embeddedServer.applicationContext

    @Shared
    HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)

    @Shared
    BlockingHttpClient client = httpClient.toBlocking()

    String yamlConfig = '''\
//tag::yamlconfig[]
micronaut:
  security:
    authentication: session
    redirect:
      login-failure: /login/authFailed
'''//end::yamlconfig[]

    static Map<String, Object> configMap = ['micronaut': [
            'security': [
                    'authentication': 'session',
                    'redirect': [
                            'login-failure': '/login/authFailed',
                    ]
            ]
        ]
    ]


    @Override
    Browser getBrowser() {
        Browser browser = super.getBrowser()
        if (embeddedServer) {
            browser.baseUrl = BaseUrlUtils.getBaseUrl(embeddedServer)
        }
        browser
    }

    Map<String, Object> getConfiguration() {
        ConfigurationUtils.getConfiguration('SessionAuthenticationSpec') +
        [
                'spec.name': 'securitysession',
                'micronaut.http.client.followRedirects': false,
        ] + flatten(configMap)
    }

    def "verify session based authentication works"() {
        when:
        to HomePage

        then:
        at HomePage

        when:
        HomePage homePage = browser.page HomePage

        then:
        homePage.username() == null

        when:
        homePage.login()

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('foo', 'foo')

        then:
        at LoginPage

        and:
        loginPage.hasErrors()

        when:
        loginPage.login('sherlock', 'password')

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == 'sherlock'

        when:
        homePage.logout()

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == null
    }

    def "verify session based authentication works without a real browser"() {
        given:
        applicationContext.getBean(HomeController)
        applicationContext.getBean(LoginAuthController)
        applicationContext.getBean(AuthenticationProviderUserPassword)

        when:
        Map m = new Yaml().load(cleanYamlAsciidocTag(yamlConfig))

        then:
        m == configMap

        when:
        HttpRequest request = HttpRequest.GET('/')
        HttpResponse<String> rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'foo', password: 'foo'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        and: 'login fails, cookie is not set'
        !loginRsp.getHeaders().get('Set-Cookie')

        when:
        loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie
        cookie.contains('SESSION=')
        cookie.endsWith('; HTTPOnly')

        when:

        String sessionId = cookie.split(";")[0].split("=")[1]
        request = HttpRequest.GET('/').cookie(Cookie.of('SESSION', sessionId))
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')
    }
}
