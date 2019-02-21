package org.springframework.web.socket.server;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.socket.WebSocketHandler;

import java.util.Map;

/**
 * Interceptor for WebSocket handshake requests. Can be used to inspect the
 * handshake request and response as well as to pass attributes to the target
 * {@link WebSocketHandler}.
 *
 * @author Rossen Stoyanchev
 * @since 4.0
 * @see org.springframework.web.socket.server.support.WebSocketHttpRequestHandler
 * @see org.springframework.web.socket.sockjs.transport.handler.DefaultSockJsService
 */
public interface HandshakeInterceptor {

    /**
     * Invoked before the handshake is processed.
     * @param request the current request
     * @param response the current response
     * @param wsHandler the target WebSocket handler
     * @param attributes attributes from the HTTP handshake to associate with the WebSocket
     * session; the provided attributes are copied, the original map is not used.
     * @return whether to proceed with the handshake ({@code true}) or abort ({@code false})
     */
    boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                            WebSocketHandler wsHandler, Map<String, Object> attributes) throws Exception;

    /**
     * Invoked after the handshake is done. The response status and headers indicate
     * the results of the handshake, i.e. whether it was successful or not.
     * @param request the current request
     * @param response the current response
     * @param wsHandler the target WebSocket handler
     * @param exception an exception raised during the handshake, or {@code null} if none
     */
    void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                        WebSocketHandler wsHandler, Exception exception);

}
