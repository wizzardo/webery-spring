package org.springframework.web.bind.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequestAttribute {
    String value() default "";

    String name() default "";

    /**
     * Whether the request attribute is required.
     * <p>Defaults to {@code true}, leading to an exception being thrown if
     * the attribute is missing. Switch this to {@code false} if you prefer
     * a {@code null} or Java 8 {@code java.util.Optional} if the attribute
     * doesn't exist.
     */
    boolean required() default true;
}
