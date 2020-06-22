package io.micronaut.security.session;

import geb.Page

class SecuredPage extends Page {

    static url = '/secured'

    static at = { title == 'Secured Page' }
}
