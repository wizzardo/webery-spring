package org.springframework.util;

public class Assert {

    public static void notNull(Object o, String message) {
        if (o == null)
            throw new IllegalArgumentException(message);
    }

    public static void isTrue(boolean b, String message) {
        if (!b)
            throw new IllegalArgumentException(message);
    }

    public static void hasLength(String s, String message) {
        if (s == null || s.isEmpty())
            throw new IllegalArgumentException(message);
    }
}
