package io.micronaut.security.pages

import geb.Page

class HomePage extends Page {

    static url = '/'

    static at = { title == 'Home' }

    static content = {
        loginLink { $('a', text: 'Login') }
        logoutButton { $('input', type: 'submit', value: 'Logout') }
        usernameElement(required: false) { $('h1 span', 0) }
        body { $('body') }
    }

    String getMessage() {
        body.text().trim()
    }

    String username() {
        if ( usernameElement.empty ) {
            return null
        }
        usernameElement.text()
    }

    void login() {
        loginLink.click()
    }

    void logout() {
        logoutButton.click()
    }
}

