package io.micronaut.security.oauth2.e2e

import geb.Page

class HomePage extends Page {

    static at = { title == "Home" }

    static content = {
        body { $('body') }
    }

    String getMessage() {
        body.text().trim()
    }
}
