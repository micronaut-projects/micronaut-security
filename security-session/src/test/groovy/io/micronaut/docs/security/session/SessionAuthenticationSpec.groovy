package io.micronaut.docs.security.session

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import org.yaml.snakeyaml.Yaml

class SessionAuthenticationSpec extends GebEmbeddedServerSpecification implements YamlAsciidocTagCleaner {

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
    Map<String, Object> getConfiguration() {
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
        applicationContext.getBean(HomeController.class)
        applicationContext.getBean(LoginAuthController.class)
        applicationContext.getBean(AuthenticationProviderUserPassword.class)

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
        println cookie
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
