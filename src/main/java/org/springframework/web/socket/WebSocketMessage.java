package org.springframework.web.socket;

/**
 * A message that can be handled or sent on a WebSocket connection.
 *
 * @author Rossen Stoyanchev
 * @since 4.0
 */
public interface WebSocketMessage<T> {

    /**
     * Return the message payload (never {@code null}).
     */
    T getPayload();

    /**
     * Return the number of bytes contained in the message.
     */
    int getPayloadLength();

    /**
     * When partial message support is available and requested via
     * {@link org.springframework.web.socket.WebSocketHandler#supportsPartialMessages()},
     * this method returns {@code true} if the current message is the last part of the
     * complete WebSocket message sent by the client. Otherwise {@code false} is returned
     * if partial message support is either not available or not enabled.
     */
    boolean isLast();

}
