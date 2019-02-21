package org.springframework.http.server;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpRequest;

import java.net.InetSocketAddress;
import java.security.Principal;

/**
 * Represents a server-side HTTP request.
 *
 * @author Arjen Poutsma
 * @author Rossen Stoyanchev
 * @since 3.0
 */
public interface ServerHttpRequest extends HttpRequest, HttpInputMessage {

    /**
     * Return a {@link Principal} instance containing the name of the
     * authenticated user. If the user has not been authenticated, the method returns
     * <code>null</code>.
     */
    Principal getPrincipal();

    /**
     * Return the address on which the request was received.
     */
    InetSocketAddress getLocalAddress();

    /**
     * Return the address of the remote client.
     */
    InetSocketAddress getRemoteAddress();

    /**
     * Return a control that allows putting the request in asynchronous mode so the
     * response remains open until closed explicitly from the current or another thread.
     */
    ServerHttpAsyncRequestControl getAsyncRequestControl(ServerHttpResponse response);

}

