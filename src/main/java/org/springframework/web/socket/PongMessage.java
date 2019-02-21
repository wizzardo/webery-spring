package org.springframework.web.socket;

import java.nio.ByteBuffer;

/**
 * A WebSocket pong message.
 *
 * @author Rossen Stoyanchev
 * @since 4.0
 */
public final class PongMessage extends AbstractWebSocketMessage<ByteBuffer> {

    /**
     * Create a new pong message with an empty payload.
     */
    public PongMessage() {
        super(ByteBuffer.allocate(0));
    }

    /**
     * Create a new pong message with the given ByteBuffer payload.
     * @param payload the non-null payload
     */
    public PongMessage(ByteBuffer payload) {
        super(payload);
    }


    @Override
    public int getPayloadLength() {
        return (getPayload() != null ? getPayload().remaining() : 0);
    }

    @Override
    protected String toStringPayload() {
        return (getPayload() != null ? getPayload().toString() : null);
    }

}
