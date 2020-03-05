
package io.micronaut.testutils

trait YamlAsciidocTagCleaner {

    String cleanYamlAsciidocTag(String str, String tagName = 'yamlconfig') {
        str.replaceAll('//tag::'+tagName+'\\[]', '').replaceAll('//end::'+tagName+'\\[]', '').trim()
    }

    Map flatten(Map m, String separator = '.') {
        m.collectEntries { k, v ->  v instanceof Map ? flatten(v, separator).collectEntries { q, r ->  [(k + separator + q): r] } : [(k):v] }
    }
}
