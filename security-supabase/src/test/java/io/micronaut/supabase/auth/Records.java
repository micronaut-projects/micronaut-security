package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import org.jspecify.annotations.Nullable;

/**
 * Builds record instances for validation tests.
 */
public final class Records {

    private Records() {
    }

    /**
     * Returns a copy of {@code sample} with the component named {@code property} replaced by {@code value}.
     * The copy is built through the record's {@link BeanIntrospection}, bypassing nullability checks so that
     * invalid instances can be handed to the validator.
     *
     * @param sample Fully populated record
     * @param property Record component to replace
     * @param value Replacement value, possibly {@code null}
     * @param <T> Record type
     * @return A new instance of the record
     */
    public static <T> T with(T sample, String property, @Nullable Object value) {
        @SuppressWarnings("unchecked")
        BeanIntrospection<T> introspection = (BeanIntrospection<T>) BeanIntrospection.getIntrospection(sample.getClass());
        Argument<?>[] arguments = introspection.getConstructorArguments();
        Object[] values = new Object[arguments.length];
        boolean found = false;
        for (int i = 0; i < arguments.length; i++) {
            String name = arguments[i].getName();
            if (name.equals(property)) {
                values[i] = value;
                found = true;
            } else {
                values[i] = introspection.getRequiredProperty(name, Object.class).get(sample);
            }
        }
        if (!found) {
            throw new IllegalArgumentException(sample.getClass().getSimpleName() + " has no component named " + property);
        }
        return introspection.instantiate(false, values);
    }
}
