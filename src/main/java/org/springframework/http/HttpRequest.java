package org.springframework.http;

import java.net.URI;

/**
 * Represents an HTTP request message, consisting of
 * {@linkplain #getMethod() method} and {@linkplain #getURI() uri}.
 *
 * @author Arjen Poutsma
 * @since 3.1
 */
public interface HttpRequest extends HttpMessage {

    /**
     * Return the HTTP method of the request.
     * @return the HTTP method as an HttpMethod enum value, or {@code null}
     * if not resolvable (e.g. in case of a non-standard HTTP method)
     */
    HttpMethod getMethod();

    /**
     * Return the URI of the request (including a query string if any,
     * but only if it is well-formed for a URI representation).
     * @return the URI of the request (never {@code null})
     */
    URI getURI();

}
