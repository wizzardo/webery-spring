package org.springframework.core.io;

import java.io.InputStream;

public class ClassPathResource {
    final String path;

    public ClassPathResource(String path) {
        this.path = path;
    }

    public InputStream getInputStream() {
        return ClassPathResource.class.getResourceAsStream(path);
    }
}
