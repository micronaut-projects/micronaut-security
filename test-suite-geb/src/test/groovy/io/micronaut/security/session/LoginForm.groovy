package io.micronaut.security.session

import groovy.transform.CompileStatic
import io.micronaut.core.annotation.Introspected

@CompileStatic
@Introspected
class LoginForm {
    String username
    String password
}
