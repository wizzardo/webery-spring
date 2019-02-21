package org.springframework.web.socket;

import java.util.List;
import java.util.Map;


/**
 * Represents a WebSocket extension as defined in the RFC 6455.
 * WebSocket extensions add protocol features to the WebSocket protocol. The extensions
 * used within a session are negotiated during the handshake phase as follows:
 * <ul>
 * <li>the client may ask for specific extensions in the HTTP handshake request</li>
 * <li>the server responds with the final list of extensions to use in the current session</li>
 * </ul>
 *
 * <p>WebSocket Extension HTTP headers may include parameters and follow
 * <a href="http://tools.ietf.org/html/rfc7230#section-3.2">RFC 7230 section 3.2</a></p>
 *
 * <p>Note that the order of extensions in HTTP headers defines their order of execution,
 * e.g. extensions "foo, bar" will be executed as "bar(foo(message))".</p>
 *
 * @author Brian Clozel
 * @author Juergen Hoeller
 * @see <a href="https://tools.ietf.org/html/rfc6455#section-9">WebSocket Protocol Extensions, RFC 6455 - Section 9</a>
 * @since 4.0
 */
public class WebSocketExtension {

    private final String name;

    private final Map<String, String> parameters;


    /**
     * Create a WebSocketExtension with the given name.
     *
     * @param name the name of the extension
     */
    public WebSocketExtension(String name) {
        this(name, null);
    }

    /**
     * Create a WebSocketExtension with the given name and parameters.
     *
     * @param name       the name of the extension
     * @param parameters the parameters
     */
    public WebSocketExtension(String name, Map<String, String> parameters) {
        throw new IllegalStateException("No extensions are supported yet");
    }


    /**
     * Return the name of the extension (never {@code null) or empty}.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Return the parameters of the extension (never {@code null}).
     */
    public Map<String, String> getParameters() {
        return this.parameters;
    }


    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        WebSocketExtension otherExt = (WebSocketExtension) other;
        return (this.name.equals(otherExt.name) && this.parameters.equals(otherExt.parameters));
    }

    @Override
    public int hashCode() {
        return this.name.hashCode() * 31 + this.parameters.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder str = new StringBuilder();
        str.append(this.name);
        for (Map.Entry<String, String> entry : this.parameters.entrySet()) {
            str.append(';');
            str.append(entry.getKey());
            str.append('=');
            str.append(entry.getValue());
        }
        return str.toString();
    }


    /**
     * Parse the given, comma-separated string into a list of {@code WebSocketExtension} objects.
     * <p>This method can be used to parse a "Sec-WebSocket-Extension" header.
     *
     * @param extensions the string to parse
     * @return the list of extensions
     * @throws IllegalArgumentException if the string cannot be parsed
     */
    public static List<WebSocketExtension> parseExtensions(String extensions) {
        throw new IllegalStateException("No extensions are supported yet");
    }
}

