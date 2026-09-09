package com.fikua.dss.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

// TEMPORARY: diagnosing NPE on hashesBase64 (Altia CSC v2 signHash 500s).
// Logs the raw request body so we can see the actual field names sent by
// the caller before Jackson binds it to SignHashRequest. Remove once the
// root cause is confirmed.
@Component
public class SignHashRawBodyLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SignHashRawBodyLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!"/csc/v2/signatures/signHash".equals(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        var wrapped = new ContentCachingRequestWrapper(request);
        chain.doFilter(wrapped, response);
        var body = wrapped.getContentAsByteArray();
        log.warn("Raw signHash request body: {}", new String(body, StandardCharsets.UTF_8));
    }
}
