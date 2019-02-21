package com.wizzardo.spring;

import com.wizzardo.http.request.Request;
import com.wizzardo.http.response.Response;
import com.wizzardo.http.response.Status;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpResponse;

import java.io.OutputStream;

public class ServerHttpResponseWrapper implements ServerHttpResponse {

    public final Request request;
    public final Response response;
    private HttpHeaders headers;

    public ServerHttpResponseWrapper(Request request, Response response) {
        this.response = response;
        this.request = request;
    }

    @Override
    public void setStatusCode(HttpStatus status) {
        response.setStatus(Status.valueOf(status.value()));
    }

    @Override
    public void flush() {
        if (headers != null)
            headers.forEach((k, strings) -> strings.forEach(v -> response.appendHeader(k, v)));
        response.commit(request.connection());
        request.connection().flush();
    }

    @Override
    public void close() {
        request.connection().close();
    }

    @Override
    public OutputStream getBody() {
        return response.getOutputStream(request.connection());
    }

    @Override
    public HttpHeaders getHeaders() {
        if (headers == null)
            headers = new HttpHeaders();

        return headers;
    }
}
