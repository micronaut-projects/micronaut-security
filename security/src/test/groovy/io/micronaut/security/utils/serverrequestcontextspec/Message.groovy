package io.micronaut.security.utils.serverrequestcontextspec

import groovy.transform.CompileStatic
import io.micronaut.serde.annotation.Serdeable

@CompileStatic
@Serdeable
class Message {
    String message

    Message() {}

    Message(String message) {
        this.message = message
    }
}
