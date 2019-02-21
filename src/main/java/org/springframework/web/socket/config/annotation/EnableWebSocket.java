package org.springframework.web.socket.config.annotation;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Add this annotation to an {@code @Configuration} class to configure
 * processing WebSocket requests:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSocket
 * public class MyWebSocketConfig {
 *
 * }
 * </pre>
 *
 * <p>Customize the imported configuration by implementing the
 * {@link WebSocketConfigurer} interface:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSocket
 * public class MyConfiguration implements WebSocketConfigurer {
 *
 * 	   &#064;Override
 * 	   public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
 *         registry.addHandler(echoWebSocketHandler(), "/echo").withSockJS();
 * 	   }
 *
 *	   &#064;Bean
 *	   public WebSocketHandler echoWebSocketHandler() {
 *         return new EchoWebSocketHandler();
 *     }
 * }
 * </pre>
 *
 * @author Rossen Stoyanchev
 * @since 4.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(DelegatingWebSocketConfiguration.class)
public @interface EnableWebSocket {
}

