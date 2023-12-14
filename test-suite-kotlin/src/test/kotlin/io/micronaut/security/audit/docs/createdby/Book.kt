package io.micronaut.security.audit.docs.createdby
//tag::clazz[]
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.security.annotation.CreatedBy
import io.micronaut.security.annotation.UpdatedBy

@MappedEntity //1
data class Book(
    @field:Id
    @field:GeneratedValue(GeneratedValue.Type.AUTO)
    var id: Long? = null,
    var title: String,
    var author: String,
    @field:CreatedBy //2
    var creator: String? = null,
    @UpdatedBy //3
    var editor: String? = null
)
//end::clazz[]
