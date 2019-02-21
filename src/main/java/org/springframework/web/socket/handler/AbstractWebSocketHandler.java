package org.springframework.web.socket.handler;

import org.springframework.web.socket.*;

/**
 * A convenient base class for {@link WebSocketHandler} implementation with empty methods.
 *
 * @author Rossen Stoyanchev
 * @author Phillip Webb
 * @since 4.0
 */
public abstract class AbstractWebSocketHandler implements WebSocketHandler {

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
    }

    @Override
    public void handleMessage(WebSocketSession session, WebSocketMessage<?> message) throws Exception {
        if (message instanceof TextMessage) {
            handleTextMessage(session, (TextMessage) message);
        }
        else if (message instanceof BinaryMessage) {
            handleBinaryMessage(session, (BinaryMessage) message);
        }
        else if (message instanceof PongMessage) {
            handlePongMessage(session, (PongMessage) message);
        }
        else {
            throw new IllegalStateException("Unexpected WebSocket message type: " + message);
        }
    }

    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
    }

    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
    }

    protected void handlePongMessage(WebSocketSession session, PongMessage message) throws Exception {
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
    }

    @Override
    public boolean supportsPartialMessages() {
        return false;
    }

}
