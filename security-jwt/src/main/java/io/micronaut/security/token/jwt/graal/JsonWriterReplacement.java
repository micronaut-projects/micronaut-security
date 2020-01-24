/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.token.jwt.graal;

import com.oracle.svm.core.annotate.Alias;
import com.oracle.svm.core.annotate.RecomputeFieldValue;
import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;
import io.micronaut.core.annotation.Internal;
import net.minidev.json.JSONStyle;
import net.minidev.json.reader.BeansWriter;
import net.minidev.json.reader.JsonWriterI;

import java.io.IOException;

/**
 * Removes runtime ASM bytecode generation from JsonWriter for Graal.
 *
 * @author graemerocher
 * @since 1.2.2
 */
//CHECKSTYLE:OFF
@Internal
@TargetClass(className = "net.minidev.json.reader.JsonWriter")
final class JsonWriterReplacement {
    @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.FromAlias)
    @Alias
    public static JsonWriterI<Object> beansWriterASM = new BeansWriter();
}

@Internal
@TargetClass(className = "net.minidev.json.reader.BeansWriterASM")
final class BeansWriterASMReplacement {
    @Substitute
    public <E> void writeJSONString(E value, Appendable out, JSONStyle compression) throws IOException {
        new BeansWriter().writeJSONString(value, out, compression);
    }
}
//CHECKSTYLE:ON
