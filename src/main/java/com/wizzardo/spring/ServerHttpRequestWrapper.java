package com.wizzardo.spring;

import com.wizzardo.http.MultiValue;
import com.wizzardo.http.request.Request;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.ServerHttpAsyncRequestControl;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.Principal;
import java.util.Map;

public class ServerHttpRequestWrapper implements ServerHttpRequest {

    public final Request request;

    public ServerHttpRequestWrapper(Request request) {
        this.request = request;
    }

    @Override
    public Principal getPrincipal() {
        return null;
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return InetSocketAddress.createUnresolved(request.connection().getIp(), request.connection().getPort());
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
        return InetSocketAddress.createUnresolved(request.connection().getIp(), request.connection().getPort());
    }

    @Override
    public ServerHttpAsyncRequestControl getAsyncRequestControl(ServerHttpResponse response) {
        return null;
    }

    @Override
    public InputStream getBody() throws IOException {
        return null;
    }

    @Override
    public HttpMethod getMethod() {
        return HttpMethod.resolve(request.method().name());
    }

    @Override
    public URI getURI() {
        return URI.create(request.path().toString());
    }

    @Override
    public HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        Map<String, MultiValue<String>> map = request.headers();
        map.forEach((k, vl) -> vl.getValues().forEach(v -> headers.add(k, v)));
        return headers;
    }
}
