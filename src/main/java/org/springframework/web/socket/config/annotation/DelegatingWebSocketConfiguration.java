package org.springframework.web.socket.config.annotation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * A variation of {@link WebSocketConfigurationSupport} that detects implementations of
 * {@link WebSocketConfigurer} in Spring configuration and invokes them in order to
 * configure WebSocket request handling.
 *
 * @author Rossen Stoyanchev
 * @since 4.0
 */
@Configuration
public class DelegatingWebSocketConfiguration extends WebSocketConfigurationSupport {

    private final List<WebSocketConfigurer> configurers = new ArrayList<WebSocketConfigurer>();


    @Autowired(required = false)
    public void setConfigurers(List<WebSocketConfigurer> configurers) {
        if (configurers != null && !configurers.isEmpty()) {
            this.configurers.addAll(configurers);
        }
    }


    @Override
    protected void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        for (WebSocketConfigurer configurer : this.configurers) {
            configurer.registerWebSocketHandlers(registry);
        }
    }

}
