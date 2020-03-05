
package io.micronaut.docs.security.securityRule.intercepturlmap

import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Put

@Requires(property = 'spec.name', value = 'docsintercepturlmap')
@Controller('/books')
class BookController {

    @Get
    String index() {
        return "Index Action"
    }

    @Get('/grails')
    String grails1() {
        return "Grails Action"
    }

    @Put("/grails")
    String grails2() {
        return "Grails Action"
    }

    @Post("/grails")
    String grails3() {
        return "Grails Action"
    }
}
