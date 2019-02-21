package org.springframework.http.server;

import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;

/**
 * Represents a server-side HTTP response.
 *
 * @author Arjen Poutsma
 * @since 3.0
 */
public interface ServerHttpResponse extends HttpOutputMessage, Flushable, Closeable {

    /**
     * Set the HTTP status code of the response.
     * @param status the HTTP status as an HttpStatus enum value
     */
    void setStatusCode(HttpStatus status);

    /**
     * Ensure that the headers and the content of the response are written out.
     * <p>After the first flush, headers can no longer be changed.
     * Only further content writing and content flushing is possible.
     */
    @Override
    void flush() throws IOException;

    /**
     * Close this response, freeing any resources created.
     */
    @Override
    void close();

}

