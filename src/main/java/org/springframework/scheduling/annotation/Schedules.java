package org.springframework.scheduling.annotation;

import java.lang.annotation.*;

/**
 * Container annotation that aggregates several {@link Scheduled} annotations.
 *
 * <p>Can be used natively, declaring several nested {@link Scheduled} annotations.
 * Can also be used in conjunction with Java 8's support for repeatable annotations,
 * where {@link Scheduled} can simply be declared several times on the same method,
 * implicitly generating this container annotation.
 *
 * <p>This annotation may be used as a <em>meta-annotation</em> to create custom
 * <em>composed annotations</em>.
 *
 * @author Juergen Hoeller
 * @since 4.0
 * @see Scheduled
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Schedules {

    Scheduled[] value();

}

