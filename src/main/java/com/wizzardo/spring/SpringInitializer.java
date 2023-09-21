package com.wizzardo.spring;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.jul.LevelChangePropagator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import com.wizzardo.http.*;
import com.wizzardo.http.framework.*;
import com.wizzardo.http.framework.di.Dependency;
import com.wizzardo.http.framework.di.DependencyFactory;
import com.wizzardo.http.framework.di.SingletonDependency;
import com.wizzardo.http.framework.message.MessageBundle;
import com.wizzardo.http.framework.parameters.ParametersHelper;
import com.wizzardo.http.framework.template.ResourceTools;
import com.wizzardo.http.request.Header;
import com.wizzardo.http.request.MultiPartEntry;
import com.wizzardo.http.request.MultiPartFileEntry;
import com.wizzardo.http.request.Request;
import com.wizzardo.http.response.JsonResponseHelper;
import com.wizzardo.http.response.Response;
import com.wizzardo.http.response.Status;
import com.wizzardo.http.websocket.Frame;
import com.wizzardo.http.websocket.Message;
import com.wizzardo.tools.cache.Cache;
import com.wizzardo.tools.collections.CollectionTools;
import com.wizzardo.tools.collections.flow.Flow;
import com.wizzardo.tools.evaluation.Config;
import com.wizzardo.tools.interfaces.Mapper;
import com.wizzardo.tools.misc.Pair;
import com.wizzardo.tools.misc.Stopwatch;
import com.wizzardo.tools.misc.StringConverter;
import com.wizzardo.tools.misc.Unchecked;
import com.wizzardo.tools.security.MD5;
import com.wizzardo.tools.yaml.YamlItem;
import com.wizzardo.tools.yaml.YamlObject;
import com.wizzardo.tools.yaml.YamlTools;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.socket.*;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistration;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.HandshakeHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SpringInitializer {

    static private org.slf4j.Logger log = LoggerFactory.getLogger(SpringInitializer.class);

    static AtomicInteger threadCounter = new AtomicInteger(0);

    static ExecutorService scheduledPool = Executors.newFixedThreadPool(2, r -> {
        Thread thread = new Thread(r, "scheduled-executor-" + threadCounter.incrementAndGet());
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler((t, e) -> {
            log.error("UncaughtException", e);
        });
        return thread;
    });

    protected static final Set<Class> PARSABLE_TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            String.class,
            Integer.class,
            Long.class,
            Short.class,
            Byte.class,
            Float.class,
            Double.class,
            Boolean.class,
            Character.class
    )));

    public void init(WebApplication app, ResourceTools tools) {
        setupLogging();

        Stopwatch stopwatch = new Stopwatch("load classes");

        List<Class> classes = tools.getClasses();
        Map<Class<?>, List<Annotation>> classMap = new LinkedHashMap<>(classes.size());
        classes.forEach(c -> classMap.put(c, getAnnotations(c)));

        System.out.println(stopwatch);

        DependencyFactory.get().register(MessageSource.class, new SpringMessageBundle());
        DependencyFactory.get(MessageBundle.class).load("messages");
        DependencyFactory.get(MessageBundle.class).setDefaultLocale(new Locale("en"));

        DependencyFactory.get().addResolver(Value.class, new DependencyFactory.AnnotationDependencyResolver<Value>() {
            @Override
            public <T> Dependency<T> resolve(Value annotation, Class<T> clazz) {
                Config config = Holders.getConfig();
                String value = annotation.value();
                value = value.substring(2, value.length() - 1);
                String[] path = value.split("\\.");
                for (int i = 0; i < path.length - 1; i++) {
                    config = config.config(path[i]);
                }
                StringConverter converter = StringConverter.getConverter(clazz);
                T v = (T) converter.convert(config.get(path[path.length - 1], ""));
                return new SingletonDependency<T>(v);
            }
        });

        initEnvironment(app);

        SpringIntegrationConfig springConfig = DependencyFactory.get(SpringIntegrationConfig.class);

        stopwatch = new Stopwatch("initComponents");
        List<Class<?>> components = initComponents(classMap);
        System.out.println(stopwatch);

        if (Boolean.valueOf(springConfig.withRestControllers)) {
            stopwatch = new Stopwatch("initRestControllers");
            initRestControllers(app, components, classMap);
            System.out.println(stopwatch);
        }

        if (Boolean.valueOf(springConfig.withWebsockets)) {
            stopwatch = new Stopwatch("initWebsockets");
            initWebsockets(app, classes);
            System.out.println(stopwatch);
        }

        if (Boolean.valueOf(springConfig.withScheduled)) {
            stopwatch = new Stopwatch("initSchedulers");
            initSchedulers(classes);
            System.out.println(stopwatch);
        }
    }

    public static class SpringIntegrationConfig implements com.wizzardo.http.framework.Configuration {

        public String withRestControllers;
        public String withWebsockets;
        public String withScheduled;

        @Override
        public String prefix() {
            return "webery.spring";
        }
    }

    protected static Cache<ScheduledRunnable, Boolean> scheduledMethods = new Cache<>("scheduledMethods", 1);

    protected static class ScheduledRunnable implements Runnable {
        protected final String name;
        protected final long fixedDelay;
        protected final long fixedRate;
        protected final long initialDelay;
        protected final Runnable runnable;
        protected final AtomicInteger counter = new AtomicInteger(0);

        ScheduledRunnable(String name, long fixedDelay, long fixedRate, long initialDelay, Runnable runnable) {
            this.name = name;
            this.fixedDelay = fixedDelay;
            this.fixedRate = fixedRate;
            this.initialDelay = initialDelay;
            this.runnable = runnable;
        }

        @Override
        public void run() {
            runnable.run();
        }
    }

    protected void executeScheduled(ScheduledRunnable scheduled) {
        System.out.println("executing " + scheduled.name);
        scheduled.counter.incrementAndGet();
        scheduled.run();
    }

    protected void initSchedulers(List<Class> classes) {
        scheduledMethods.onRemove((scheduled, aBoolean) -> {
            long start = System.currentTimeMillis();
            scheduledPool.execute(() -> {
                try {
                    executeScheduled(scheduled);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    long stop = System.currentTimeMillis();
                    if (scheduled.fixedDelay != -1) {
                        scheduledMethods.put(scheduled, true, scheduled.fixedDelay);
                    } else if (scheduled.fixedRate != -1) {
                        long delay = scheduled.fixedRate - (stop - start);
                        if (delay <= 0)
                            delay = scheduled.fixedRate;

                        scheduledMethods.put(scheduled, true, delay);
                    }
                }
            });
        });

        classes.stream()
                .forEach(aClass -> {
                    Arrays.stream(aClass.getMethods())
                            .filter(method -> method.isAnnotationPresent(Scheduled.class))
                            .forEach(method -> {
                                Scheduled a = method.getAnnotation(Scheduled.class);
                                if (!a.cron().isEmpty())
                                    throw new IllegalArgumentException("Cron expression is not supported yet");

                                if (a.fixedDelay() < 0 && a.fixedRate() < 0)
                                    throw new IllegalArgumentException("fixedRate or fixedDelay should be specified");

                                ScheduledRunnable scheduledRunnable = new ScheduledRunnable(method.toString(), a.fixedDelay(), a.fixedRate(), a.initialDelay(),
                                        () -> Unchecked.run(() -> method.invoke(DependencyFactory.get(aClass))));

                                if (scheduledRunnable.initialDelay > 0)
                                    scheduledMethods.put(scheduledRunnable, true, scheduledRunnable.initialDelay);
                                else
                                    scheduledMethods.put(scheduledRunnable, true);
                            });
                });
    }

    protected void initWebsockets(WebApplication app, List<Class> classes) {
        classes.stream()
                .filter(aClass -> WebSocketConfigurer.class.isAssignableFrom(aClass))
                .filter(aClass -> aClass.isAnnotationPresent(Configuration.class))
                .filter(aClass -> aClass.isAnnotationPresent(EnableWebSocket.class))
                .map(aClass -> DependencyFactory.get(aClass))
                .map(o -> (WebSocketConfigurer) o)
                .forEach(webSocketConfigurer -> {
                    System.out.println("registering websocket with " + webSocketConfigurer.getClass());
                    webSocketConfigurer.registerWebSocketHandlers(createWebsocketHandlerRegistry(app));
                });
    }

    protected WebSocketHandlerRegistry createWebsocketHandlerRegistry(WebApplication app) {
        return new MyWebSocketHandlerRegistry(app);
    }

    protected void setupLogging() {
        Config logging = Holders.getConfig().config("logging");

        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        lc.reset();

        LevelChangePropagator levelChangePropagator = new LevelChangePropagator();
        levelChangePropagator.setResetJUL(true);
        lc.addListener(levelChangePropagator);

        String consolePattern = logging.config("pattern").get("console", "");
        if (!consolePattern.isEmpty()) {
            PatternLayoutEncoder ple = new PatternLayoutEncoder();
            ple.setPattern(consolePattern);
            ple.setContext(lc);
            ple.start();

            ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
            consoleAppender.setEncoder(ple);
            consoleAppender.setContext(lc);
            consoleAppender.start();


            for (Pair<String, Level> level : getLogLevels(logging.config("level"), new ArrayList<>())) {
                System.out.println("setting logging level: " + level);
                Logger logger = (Logger) LoggerFactory.getLogger(level.key);
                logger.addAppender(consoleAppender);
                logger.setLevel(level.value);
                logger.setAdditive(false); /* set to true if root should log too */
            }
        }
    }

    protected List<Pair<String, Level>> getLogLevels(Config config, List<Pair<String, Level>> list) {
        for (Map.Entry<String, Object> entry : config.entrySet()) {
            if (entry.getValue() instanceof Config) {
                getLogLevels((Config) entry.getValue(), list);
            } else {
                Level level = Level.valueOf(String.valueOf(entry.getValue()));
                ArrayList<String> parts = new ArrayList<>();
                parts.add(entry.getKey());
                Config c = config;
                while (!c.name().equals("level")) {
                    parts.add(c.name());
                    c = c.parent();
                }
                Collections.reverse(parts);
                list.add(Pair.of(CollectionTools.join(parts, "."), level));
            }
        }
        return list;
    }

    protected void initEnvironment(WebApplication app) {
        Environment environment = new Environment() {
            @Override
            public boolean containsProperty(String key) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String getProperty(String key) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String getProperty(String key, String defaultValue) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public <T> T getProperty(String key, Class<T> targetType) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public <T> T getProperty(String key, Class<T> targetType, T defaultValue) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public <T> Class<T> getPropertyAsClass(String key, Class<T> targetType) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String getRequiredProperty(String key) throws IllegalStateException {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public <T> T getRequiredProperty(String key, Class<T> targetType) throws IllegalStateException {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String resolvePlaceholders(String text) {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String resolveRequiredPlaceholders(String text) throws IllegalArgumentException {
                throw new IllegalStateException("Not implemented yet");
            }

            @Override
            public String[] getActiveProfiles() {
                return app.getProfiles().toArray(new String[0]);
            }

            @Override
            public String[] getDefaultProfiles() {
                return new String[0];
            }

            @Override
            public boolean acceptsProfiles(String... profiles) {
                for (String profile : profiles) {
                    if (!app.getProfiles().contains(profile)) {
                        return false;
                    }
                }
                return true;
            }
        };

        DependencyFactory.get().register(Environment.class, new SingletonDependency<>(environment));
    }

    protected void initRestControllers(WebApplication app, List<Class<?>> components, Map<Class<?>, List<Annotation>> classMap) {
        Map<String, RestHandler> handlers = new HashMap<>();
        components.stream()
                .filter(aClass -> classMap.get(aClass).stream().filter(annotation -> annotation instanceof RestController).findAny().isPresent())
                .forEach(aClass -> {
                    Object controller = DependencyFactory.get(aClass);

                    Arrays.stream(aClass.getMethods())
                            .filter(method -> method.isAnnotationPresent(GetMapping.class)
                                    || method.isAnnotationPresent(PostMapping.class)
                                    || method.isAnnotationPresent(PutMapping.class)
                                    || method.isAnnotationPresent(DeleteMapping.class)
                                    || method.isAnnotationPresent(PatchMapping.class)
                            )
                            .forEach(method -> {
                                Handler handler = createHandler(controller, method);
                                GetMapping getMapping = method.getAnnotation(GetMapping.class);
                                if (getMapping != null) {
                                    Stream.concat(Arrays.stream(getMapping.path()), Arrays.stream(getMapping.value()))
                                            .forEach(path -> getRestHandler(app, handlers, path).get(handler));
                                }
                                PostMapping postMapping = method.getAnnotation(PostMapping.class);
                                if (postMapping != null) {
                                    Stream.concat(Arrays.stream(postMapping.path()), Arrays.stream(postMapping.value()))
                                            .forEach(path -> getRestHandler(app, handlers, path).post(handler));
                                }
                                PutMapping putMapping = method.getAnnotation(PutMapping.class);
                                if (putMapping != null) {
                                    Stream.concat(Arrays.stream(putMapping.path()), Arrays.stream(putMapping.value()))
                                            .forEach(path -> getRestHandler(app, handlers, path).put(handler));
                                }
                                DeleteMapping deleteMapping = method.getAnnotation(DeleteMapping.class);
                                if (deleteMapping != null) {
                                    Stream.concat(Arrays.stream(deleteMapping.path()), Arrays.stream(deleteMapping.value()))
                                            .forEach(path -> getRestHandler(app, handlers, path).delete(handler));
                                }
                                PatchMapping patchMapping = method.getAnnotation(PatchMapping.class);
                                if (patchMapping != null) {
                                    throw new IllegalArgumentException("PatchMapping is not supported yet");
                                }
                            });
                });
    }

    public static class MyWebSocketHandlerRegistry implements WebSocketHandlerRegistry {
        final WebApplication application;

        public MyWebSocketHandlerRegistry(WebApplication application) {
            this.application = application;
        }

        @Override
        public WebSocketHandlerRegistration addHandler(WebSocketHandler webSocketHandler, String... paths) {
            SpringWebSocketHandlerRegistration webSocketHandlerRegistration = new SpringWebSocketHandlerRegistration(application, webSocketHandler, paths);
            return webSocketHandlerRegistration;
        }

        protected class SpringWebSocketHandlerRegistration implements WebSocketHandlerRegistration {
            final WebApplication application;
            List<HandshakeInterceptor> interceptors = new ArrayList<>();
            HandshakeHandler handshakeHandler;

            public SpringWebSocketHandlerRegistration(WebApplication application, WebSocketHandler handler, String... paths) {
                this.application = application;
                addHandler(handler, paths);
            }

            @Override
            public WebSocketHandlerRegistration addHandler(WebSocketHandler handler, String... paths) {
                com.wizzardo.http.websocket.WebSocketHandler<SpringWebSocketSession> wrapper = createWrapper(handler);
                for (String path : paths) {
                    application.getUrlMapping().append(path, wrapper);
                }
                return this;
            }

            protected com.wizzardo.http.websocket.WebSocketHandler<SpringWebSocketSession> createWrapper(WebSocketHandler webSocketHandler) {
                return new com.wizzardo.http.websocket.WebSocketHandler<SpringWebSocketSession>() {
                    @Override
                    public void onConnect(SpringWebSocketSession listener) {
                        Unchecked.run(() -> webSocketHandler.afterConnectionEstablished(listener));
                    }

                    @Override
                    public void onDisconnect(SpringWebSocketSession listener) {
                        Unchecked.run(() -> webSocketHandler.afterConnectionClosed(listener, CloseStatus.NO_STATUS_CODE));
                    }

                    @Override
                    public void onMessage(SpringWebSocketSession listener, Message message) {
                        if (message.isTextMessage())
                            Unchecked.run(() -> webSocketHandler.handleMessage(listener, new TextMessage(message.asString())));
                        else if (message.isBinaryMessage())
                            Unchecked.run(() -> webSocketHandler.handleMessage(listener, new BinaryMessage(message.asBytes())));
                        else
                            throw new IllegalArgumentException("Unknown message type: " + message.asString());
                    }

                    @Override
                    protected SpringWebSocketSession createListener(HttpConnection connection, com.wizzardo.http.websocket.WebSocketHandler handler) {
                        return new SpringWebSocketSession(connection, handler, RequestContext.get().getRequestHolder().get("WebsocketSessionAttributes"));
                    }

                    @Override
                    protected void beforeHandshake(Request request, Response response) {
                        ServerHttpRequestWrapper requestWrapper = new ServerHttpRequestWrapper(request);
                        ServerHttpResponseWrapper responseWrapper = new ServerHttpResponseWrapper(request, response);
                        Map<String, Object> attributes = new ConcurrentHashMap<>();


                        for (HandshakeInterceptor interceptor : interceptors) {
                            if (!Unchecked.call(() -> interceptor.beforeHandshake(requestWrapper, responseWrapper, webSocketHandler, attributes))) {
                                responseWrapper.flush();
                                return;
                            }
                        }

                        Exception handshakeException = null;
                        try {
                            if (handshakeHandler != null)
                                if (!handshakeHandler.doHandshake(requestWrapper, responseWrapper, webSocketHandler, attributes)) {
                                    responseWrapper.flush();
                                    return;
                                }

                        } catch (Exception e) {
                            handshakeException = e;
                        }

                        for (HandshakeInterceptor interceptor : interceptors) {
                            interceptor.afterHandshake(requestWrapper, responseWrapper, webSocketHandler, handshakeException);
                        }

                        RequestContext.get().getRequestHolder().put("WebsocketSessionAttributes", attributes);
                    }
                };
            }

            @Override
            public WebSocketHandlerRegistration setHandshakeHandler(HandshakeHandler handshakeHandler) {
                this.handshakeHandler = handshakeHandler;
                return this;
            }

            @Override
            public WebSocketHandlerRegistration addInterceptors(HandshakeInterceptor... interceptors) {
                this.interceptors.addAll(Arrays.asList(interceptors));
                return this;
            }

            @Override
            public WebSocketHandlerRegistration setAllowedOrigins(String... origins) {
                //todo add restrictions
                return this;
            }
        }

        static class SpringWebSocketSession extends com.wizzardo.http.websocket.WebSocketHandler.WebSocketListener implements WebSocketSession {
            protected Map<String, Object> attributes;
            protected final String id = createSessionId();

            static synchronized String createSessionId() {
                return MD5.create().update(String.valueOf(System.nanoTime())).asString();
            }

            public SpringWebSocketSession(HttpConnection connection, com.wizzardo.http.websocket.WebSocketHandler webSocketHandler, Map<String, Object> attributes) {
                super(connection, webSocketHandler);
                this.attributes = attributes;
            }

            @Override
            public String getId() {
                return id;
            }

            @Override
            public URI getUri() {
                return URI.create(getRequest().path().toString());
            }

            @Override
            public HttpHeaders getHandshakeHeaders() {
                HttpHeaders headers = new HttpHeaders();
                Map<String, MultiValue<String>> map = getRequest().headers();
                map.forEach((k, vl) -> vl.getValues().forEach(v -> headers.add(k, v)));
                return headers;
            }

            @Override
            protected void onError(Exception e) {
                log.error("Unexpected websocket error", e);
                close(CloseStatus.SERVER_ERROR.getCode(), e.getMessage());
            }

            @Override
            public Map<String, Object> getAttributes() {
                return attributes;
            }

            @Override
            public Principal getPrincipal() {
                return null;
            }

            @Override
            public InetSocketAddress getLocalAddress() {
                return InetSocketAddress.createUnresolved(connection.getIp(), connection.getPort());
            }

            @Override
            public InetSocketAddress getRemoteAddress() {
                return InetSocketAddress.createUnresolved(connection.getIp(), connection.getPort());
            }

            @Override
            public String getAcceptedProtocol() {
                return null;
            }

            @Override
            public void setTextMessageSizeLimit(int messageSizeLimit) {
            }

            @Override
            public int getTextMessageSizeLimit() {
                return connection.getServer().getWebsocketFrameLengthLimit();
            }

            @Override
            public void setBinaryMessageSizeLimit(int messageSizeLimit) {
            }

            @Override
            public int getBinaryMessageSizeLimit() {
                return connection.getServer().getWebsocketFrameLengthLimit();
            }

            @Override
            public List<WebSocketExtension> getExtensions() {
                return Collections.emptyList();
            }

            @Override
            public void sendMessage(WebSocketMessage<?> message) throws IOException {
                Message m = new Message();
                if (message instanceof TextMessage) {
                    TextMessage text = (TextMessage) message;
                    m.append(text.asBytes());
                } else if (message instanceof BinaryMessage) {
                    BinaryMessage binary = (BinaryMessage) message;
                    if (binary.getPayload().hasArray())
                        m.append(binary.getPayload().array(), binary.getPayload().position(), binary.getPayload().limit());
                    else {
                        byte[] data = new byte[binary.getPayload().limit()];
                        binary.getPayload().get(data);
                        m.append(data);
                    }
                } else if (message instanceof PingMessage) {
                    m.add(new Frame(Frame.OPCODE_PING));
                } else if (message instanceof PongMessage) {
                    m.add(new Frame(Frame.OPCODE_PONG));
                } else {
                    throw new IllegalArgumentException("Doesn't support messages of type " + message.getClass());
                }

                sendMessage(m);
            }

            @Override
            public boolean isOpen() {
                return connection.isAlive();
            }

            @Override
            public void close(CloseStatus status) {
                close(status.getCode(), status.getReason());
            }
        }
    }

    protected RestHandler getRestHandler(WebApplication app, Map<String, RestHandler> handlers, String path) {
        path = path.replaceAll("\\{", "\\$\\{");
//        path = path.replaceAll("\\}", "}?");
        String finalPath = path;
        return handlers.computeIfAbsent(path, s -> {
            System.out.println("creating new rest handler for " + finalPath);
            RestHandler restHandler = new RestHandler()
                    .allowHeaders("token", "content-type"); // todo make this configurable
            app.getUrlMapping().append(s, restHandler);
            return restHandler;
        });
    }

    static Map<Class, ParametersHelper.ParameterMapper<?>> customParameterMappers = new HashMap<>();

    static {
        customParameterMappers.put(MultipartFile.class, (request, name, consumer) -> {
            if (!request.isMultipart())
                return;

            MultiValue<MultiPartEntry> entry = request.entries(name);
            if (entry == null)
                return;

            for (MultiPartEntry value : entry.getValues()) {
                if (value instanceof MultiPartFileEntry) {
                    MultiPartFileEntry fileEntry = (MultiPartFileEntry) value;
                    consumer.consume(new MultipartFileWrapper(fileEntry.getFile(), fileEntry.fileName(), name));
                }
            }
        });
    }

    protected Handler createHandler(Object controller, Method method) {
        Class<?> returnType = method.getReturnType();
        BiConsumer<Object, Response> resultSetter;
        if (returnType.equals(String.class)) {
            resultSetter = (o, response) -> response.body(String.valueOf(o))
                    .appendHeader(Header.KV_CONTENT_TYPE_TEXT_PLAIN);
        } else if (returnType.equals(byte[].class)) {
            resultSetter = (o, response) -> response.body((byte[]) o)
                    .appendHeader(Header.KV_CONTENT_TYPE_APPLICATION_OCTET_STREAM);
        } else if (returnType.equals(ResponseEntity.class)) {
            Type genericType = method.getGenericReturnType();
            if (genericType instanceof ParameterizedType) {
                ParameterizedType type = (ParameterizedType) genericType;

                Type subtype = type.getActualTypeArguments()[0];
                if (subtype.equals(String.class)) {
                    resultSetter = (o, response) -> {
                        ResponseEntity entity = (ResponseEntity) o;
                        response.status(Status.valueOf(entity.getStatusCodeValue()));

                        if (entity.getBody() != null)
                            response.body(String.valueOf(entity.getBody()));
                        else if (shouldAddEmptyBody(response.status()))
                            response.body(new byte[0]);

                        if (response.contentLength() != 0 && !entity.getHeaders().containsKey("Content-Type"))
                            response.appendHeader(Header.KV_CONTENT_TYPE_TEXT_PLAIN);

                        entity.getHeaders().forEach((key, values) -> values.forEach(value -> response.appendHeader(key, value)));
                    };
                } else if (subtype.equals(byte[].class)) {
                    resultSetter = (o, response) -> {
                        ResponseEntity entity = (ResponseEntity) o;
                        response.status(Status.valueOf(entity.getStatusCodeValue()));

                        if (entity.getBody() != null)
                            response.body((byte[]) entity.getBody());
                        else if (shouldAddEmptyBody(response.status()))
                            response.body(new byte[0]);

                        if (response.contentLength() != 0 && !entity.getHeaders().containsKey("Content-Type"))
                            response.appendHeader(Header.KV_CONTENT_TYPE_APPLICATION_OCTET_STREAM);

                        entity.getHeaders().forEach((key, values) -> values.forEach(value -> response.appendHeader(key, value)));
                    };
                } else {
                    resultSetter = (o, response) -> {
                        ResponseEntity entity = (ResponseEntity) o;
                        response.status(Status.valueOf(entity.getStatusCodeValue()));

                        if (entity.getBody() != null)
                            response.body(JsonResponseHelper.renderJson(entity.getBody()));
                        else if (shouldAddEmptyBody(response.status()))
                            response.body(new byte[0]);

                        if (response.contentLength() != 0 && !entity.getHeaders().containsKey("Content-Type"))
                            response.appendHeader(Header.KV_CONTENT_TYPE_APPLICATION_JSON);

                        entity.getHeaders().forEach((key, values) -> values.forEach(value -> response.appendHeader(key, value)));
                    };
                }
            } else {
                throw new IllegalStateException("ResponseEntity is ParameterizedType");
            }
        } else if (returnType.equals(void.class)) {
            resultSetter = (o, response) -> {
            };
        } else if (returnType.equals(Response.class)) {
            resultSetter = (o, response) -> {
            };
        } else
            resultSetter = (o, response) -> response.body(JsonResponseHelper.renderJson(o))
                    .appendHeader(Header.KV_CONTENT_TYPE_APPLICATION_JSON);


        CollectionTools.Closure2<Object, Request, Response> renderer;
        if (method.getParameterCount() == 0) {
            renderer = (req, res) -> Unchecked.call(() -> method.invoke(controller));
        } else {
            Parameter[] parameters = method.getParameters();
            for (Parameter parameter : parameters) {
                if (parameter.isAnnotationPresent(RequestParam.class))
                    continue;
                if (parameter.isAnnotationPresent(RequestAttribute.class))
                    continue;
                if (parameter.isAnnotationPresent(RequestHeader.class))
                    continue;
                if (parameter.isAnnotationPresent(PathVariable.class))
                    continue;
                if (parameter.isAnnotationPresent(RequestBody.class))
                    continue;

                Class<?> type = parameter.getType();
                if (type.isPrimitive() || type.isEnum() || PARSABLE_TYPES.contains(type))
                    throw new IllegalStateException("Can't parse parameters for '" + controller.getClass().getName() + "." + method.getName() + "', parameters names are not present. Please run javac with '-parameters' or add an annotation Parameter");
            }

            Mapper<Request, Object>[] argsMappers = new Mapper[parameters.length];
            Type[] types = method.getGenericParameterTypes();
            for (int i = 0; i < parameters.length; i++) {
                try {
                    Parameter parameter = parameters[i];
                    boolean required = false;
                    String name = null;
                    if (parameter.isAnnotationPresent(RequestParam.class)) {
                        RequestParam annotation = parameter.getAnnotation(RequestParam.class);
                        name = !annotation.name().isEmpty() ? annotation.name() : annotation.value();
                        String def = annotation.defaultValue().equals(ValueConstants.DEFAULT_NONE) ? null : annotation.defaultValue();

                        if (name.isEmpty())
                            throw new IllegalArgumentException("Cannot find " + i + "th parameter name");

                        argsMappers[i] = ParametersHelper.createParametersMapper(name, def, types[i], customParameterMappers);
                        required = annotation.required();
                    } else if (parameter.isAnnotationPresent(PathVariable.class)) {
                        PathVariable annotation = parameter.getAnnotation(PathVariable.class);
                        name = !annotation.name().isEmpty() ? annotation.name() : annotation.value();
                        String def = null;
                        if (name.isEmpty())
                            throw new IllegalArgumentException("Cannot find " + i + "th parameter name");

                        argsMappers[i] = ParametersHelper.createParametersMapper(name, def, types[i]);
                        required = annotation.required();
                    } else if (parameter.isAnnotationPresent(RequestAttribute.class)) {
                        RequestAttribute annotation = parameter.getAnnotation(RequestAttribute.class);
                        name = !annotation.name().isEmpty() ? annotation.name() : annotation.value();
                        if (name.isEmpty())
                            throw new IllegalArgumentException("Cannot find " + i + "th parameter name");

                        String finalName = name;
                        argsMappers[i] = request -> RequestContext.get().getRequestHolder().get(finalName);
                        required = annotation.required();
                        if (required)
                            argsMappers[i] = notNullAttribute(argsMappers[i], parameter.getType(), name, i);

                        continue;
                    } else if (parameter.isAnnotationPresent(RequestHeader.class)) {
                        RequestHeader annotation = parameter.getAnnotation(RequestHeader.class);
                        name = !annotation.name().isEmpty() ? annotation.name() : annotation.value();
                        if (name.isEmpty())
                            throw new IllegalArgumentException("Cannot find " + i + "th parameter name");

                        String def = annotation.defaultValue().equals(ValueConstants.DEFAULT_NONE) ? null : annotation.defaultValue();
                        String finalName = name;
                        if (Date.class.isAssignableFrom(parameter.getType()))
                            argsMappers[i] = request -> Unchecked.call(() -> {
                                String header = request.header(finalName, def);
                                return header == null ? null : HttpDateFormatterHolder.get().parse(header);
                            });
                        else if (String.class == parameter.getType())
                            argsMappers[i] = request -> Unchecked.call(() -> request.header(finalName, def));
                        else if (int.class == parameter.getType() || Integer.class == parameter.getType()) {
                            if (def != null) {
                                long defValue = Long.parseLong(def);
                                argsMappers[i] = request -> Unchecked.call(() -> (int) request.headerLong(finalName, defValue));
                            } else
                                argsMappers[i] = request -> Unchecked.call(() -> (int) request.headerLong(finalName));
                        } else if (long.class == parameter.getType() || Long.class == parameter.getType()) {
                            if (def != null) {
                                long defValue = Long.parseLong(def);
                                argsMappers[i] = request -> Unchecked.call(() -> request.headerLong(finalName, defValue));
                            } else
                                argsMappers[i] = request -> Unchecked.call(() -> request.headerLong(finalName));
                        } else
                            throw new IllegalArgumentException("Cannot mapper for header to type " + parameter.getType());

                        required = annotation.required();
                    } else if (parameter.isAnnotationPresent(RequestBody.class)) {
                        RequestBody annotation = parameter.getAnnotation(RequestBody.class);
                        argsMappers[i] = ParametersHelper.createParametersMapper("", null, types[i]);
                        required = annotation.required();
                    } else if (parameter.getType().equals(Request.class)) {
                        argsMappers[i] = request -> request;
                    } else if (parameter.getType().equals(Response.class)) {
                        argsMappers[i] = request -> request.response();
                    }

                    if (required)
                        argsMappers[i] = notNull(argsMappers[i], parameter.getType(), name, i);
                } catch (Exception e) {
                    throw new IllegalArgumentException("Can't create parameter mapper ' in '" + controller.getClass().getName() + "." + method.getName() + "'", e);
                }
            }
            Mapper<Request, Object[]> toArgs = request -> {
                Object[] args = new Object[argsMappers.length];
                for (int i = 0; i < argsMappers.length; i++) {
                    args[i] = argsMappers[i].map(request);
                }
                return args;
            };

            renderer = (req, res) -> {
                Object[] args = null;
                try {
                    args = toArgs.map(req);
                    return method.invoke(controller, args);
                } catch (Exception e) {
                    log.error("Unexpected exception in " + controller.getClass().getName() + "." + method.getName() + "(" + Arrays.toString(args) + ")", e);
                    throw Unchecked.rethrow(e);
                }
            };
        }


        return new Handler() {

            final String controllerName = Controller.getControllerName(controller.getClass());

            @Override
            public Response handle(Request<HttpConnection, Response> request, Response response) throws IOException {
                RequestContext context = (RequestContext) Thread.currentThread();
                context.setController(controllerName);
                context.setAction(method.getName());

                RequestContext copiedContext = context.copy();

                if (request.isMultipart() && !request.isMultiPartDataPrepared()) {
                    Handler handler = this;
                    return new MultipartHandler((req, res) -> {
                        //restoring RequestContext after reset because of async response
                        RequestContext.get().set(copiedContext);

                        return handler.handle(req, res);
                    }, 5120L * 1024 * 1024).handle(request, response); //todo read config
                }

                Object result = renderer.execute(request, response);
                resultSetter.accept(result, response);
                return response;
            }
        };
    }

    protected boolean shouldAddEmptyBody(Status status) {
        if (status.code == 204)
            return false;
        if (status.code >= 300 && status.code < 400)
            return false;

        return true;
    }

    protected Mapper<Request, Object> notNull(Mapper<Request, Object> src, Class type, String name, int number) {
        return request -> {
            Object result = src.map(request);
            if (result == null)
                throw new IllegalArgumentException(number + "th parameter (" + type.getSimpleName() + ") " + name + " must not be null");

            return result;
        };
    }

    protected Mapper<Request, Object> notNullAttribute(Mapper<Request, Object> src, Class type, String name, int number) {
        return request -> {
            Object result = src.map(request);
            if (result == null)
                throw new IllegalArgumentException("Missing request attribute '" + name + "' of type " + type.getSimpleName());

            return result;
        };
    }

    static class SpringMessageBundle implements MessageSource {
        MessageBundle bundle = DependencyFactory.get(MessageBundle.class);

        @Override
        public String getMessage(String code, Object[] args, String defaultMessage, Locale locale) {
            String s = bundle.get(locale, code, args);
            return s == null ? defaultMessage : s;
        }

        @Override
        public String getMessage(String code, Object[] args, Locale locale) throws NoSuchMessageException {
            return bundle.get(locale, code, args);
        }

        @Override
        public String getMessage(MessageSourceResolvable resolvable, Locale locale) throws NoSuchMessageException {
            throw new IllegalStateException("Not supported yet");
        }
    }

    protected List<Class<?>> initComponents(Map<Class<?>, List<Annotation>> classMap) {
        List<Class<?>> components = classMap.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(annotation -> annotation instanceof Component))
                .map(Map.Entry::getKey)
                .peek(cl -> {
//                    System.out.println("register " + cl);
//                    DependencyFactory.get().register(cl, (Dependency) new SingletonDependency<Object>(cl) {
//                        @Override
//                        protected void onCreate(Object component) {
//                            super.onCreate(component);
//                            executePostConstruct(component, cl);
//                        }
//                    });
                    registerDependency(cl);
                })
                .collect(Collectors.toList());

        components.stream()
                .forEach(clazz -> {
                    Object component = DependencyFactory.get(clazz);
                });

        return components;
    }

    public <T> void registerDependency(Class<T> cl) {
        registerDependency(cl, cl);
    }

    public <T> void registerDependency(Class<T> cl, Class<? extends T> imp) {
        DependencyFactory.get().register(cl, new SingletonDependency<T>(imp) {
            @Override
            protected void onCreate(T component) {
                super.onCreate(component);
                executePostConstruct(component, imp);
            }
        });
    }

    protected void executePostConstruct(Object component, Class<?> cl) {
        Arrays.stream(cl.getMethods())
                .filter(method -> method.isAnnotationPresent(PostConstruct.class))
                .forEach(method -> Unchecked.run(() -> method.invoke(component)));
    }

    protected List<Annotation> getAnnotations(Class clazz) {
        Set<Annotation> result = new LinkedHashSet<>();
        Annotation[] annotations = clazz.getAnnotations();
        for (Annotation annotation : annotations) {
            result.add(annotation);
            getAnnotations(annotation, result);
        }
        return result.stream()
                .filter(a -> !a.annotationType().getName().startsWith("kotlin."))
                .collect(Collectors.toList());
    }

    protected Set<Annotation> getAnnotations(Annotation a, Set<Annotation> to) {
        Annotation[] annotations = a.annotationType().getAnnotations();
        for (Annotation annotation : annotations) {
            if (to.add(annotation))
                try {
                    getAnnotations(annotation, to);
                } catch (Throwable e) {
                    e.printStackTrace();
                    System.out.println(e);
                }
        }
        return to;
    }

    public void loadConfig(WebApplication it) {
        String activeProfiles = System.getProperty("spring.profiles.active", "default");
        it.getConfig().config("spring").config("profiles").put("active", activeProfiles);

        Flow.of(activeProfiles.split(",")).each(it::addProfile).execute();

        ResourceTools resourceTools = DependencyFactory.get(ResourceTools.class);
        String text = resourceTools.getResourceAsString("application.yaml");
        String[] docs = text.split("---[\r\n]+");
        for (String doc : docs) {
            YamlObject yaml = YamlTools.parse(doc).asYamlObject();
            Config config = it.getConfig();
            if (yaml.containsKey("spring") && yaml.isYamlObject("spring")) {
                YamlObject spring = yaml.getAsYamlObject("spring");
                YamlItem item = spring.remove("profiles");
                if (item != null)
                    for (String profile : item.asString().split(", *")) {
                        populateConfig(config.config("profiles").config(profile), yaml);
                    }
                else
                    populateConfig(config, yaml);

            } else if (yaml.containsKey("spring.profiles")) {
                YamlItem item = yaml.remove("spring.profiles");
                if (item != null)
                    for (String profile : item.asString().split(", *")) {
                        populateConfig(config.config("profiles").config(profile), yaml);
                    }
                else
                    populateConfig(config, yaml);
            } else
                populateConfig(config, yaml);
        }


        Long timeout = Long.parseLong(it.getConfig().config("server").get("connection-timeout", "30000"));
        it.getConfig().config("server").put("ttl", timeout);
    }

    protected void populateConfig(Config config, YamlObject yamlObject) {
        yamlObject.forEach((key, item) -> {
            Config c = config;
            String[] path = key.split("\\.");
            for (int i = 0; i < path.length - 1; i++) {
                try {
                    c = c.config(path[i]);
                } catch (Exception e) {
                    throw new IllegalStateException("Cannot process '" + path[i] + "' from '" + key + "' as a config", e);
                }
            }
            key = path[path.length - 1];

            if (item.isYamlObject())
                populateConfig(c.config(key), item.asYamlObject());
            else if (item.isYamlArray())
                throw new IllegalStateException("Arrays in yaml config are not supported yet");
            else if (item.isNull())
                c.put(key, null);
            else
                c.put(key, item.asString());
        });
    }
}
