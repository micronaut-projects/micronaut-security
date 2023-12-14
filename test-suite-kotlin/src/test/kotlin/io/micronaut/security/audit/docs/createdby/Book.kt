package io.micronaut.security.audit.docs.createdby
//tag::clazz[]
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.security.annotation.CreatedBy
import io.micronaut.security.annotation.UpdatedBy

@MappedEntity //1
class Book {

    @Id
    @GeneratedValue
    var id: Long? = null

    var title: String? = null

    var author: String? = null

    @CreatedBy //2
    var creator: String? = null

    @UpdatedBy //3
    var editor: String? = null

}
//end::clazz[]
