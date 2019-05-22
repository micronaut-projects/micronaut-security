package io.micronaut.security.oauth2.e2e

import geb.Page

class LoginPage extends Page {

    static at = { title == 'Log in to Keycloak' }

    static content = {
        usernameInput { $('#username') }
        passwordInput { $('#password') }
        submitInput { $('#kc-login') }
    }

    void login(String username, String password) {
        usernameInput = username
        passwordInput = password
        submitInput.click()
    }
}
