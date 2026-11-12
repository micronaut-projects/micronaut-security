package io.micronaut.security.pages

import geb.Page

class KeycloakLogoutConfirmPage extends Page {

    static at = {
        title == 'Sign in to Keycloak' && $('h1#kc-page-title').text().contains('Logging out')
    }

    static content = {
        confirmLogoutButton { $('#kc-logout') } // <input id="kc-logout" ... value="Logout">
    }

    void confirm() {
        confirmLogoutButton.click()
    }
}
