package io.micronaut.security.token.jwt.cookie;

import geb.Page

class SecuredPage extends Page {

    static url = '/secured'

    static at = { title == 'Secured Page' }
}
