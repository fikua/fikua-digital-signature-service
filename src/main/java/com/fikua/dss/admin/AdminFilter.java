package com.fikua.dss.admin;

import com.fikua.dss.service.AccessTokens;
import com.fikua.dss.service.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;

/**
 * The only door to the administration API: its port, and there nothing else; a
 * valid token; and the administrators' group. Before anything reads the request.
 */
public class AdminFilter extends OncePerRequestFilter {

    static final String ADMINISTRATOR = "fikua.administrator";
    @SuppressWarnings("java:S1075") // The path of the API itself, not of another system.
    private static final String PATH = "/admin/";
    private static final String BEARER = "Bearer ";

    private final int port;
    private final String group;
    private final JwtVerifier tokens;

    public AdminFilter(int port, String group, JwtVerifier tokens) {
        this.port = port;
        this.group = group;
        this.tokens = tokens;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // The decoded path the dispatcher matches, not the raw one.
        var path = request.getServletPath() + (request.getPathInfo() == null ? "" : request.getPathInfo());
        var administration = path.startsWith(PATH);
        var here = request.getLocalPort() == port;
        if (!administration && !here) {
            chain.doFilter(request, response);
            return;
        }
        if (administration != here) {
            refuse(response, 404, "not_found");
            return;
        }
        var header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER)) {
            refuse(response, 401, "unauthorized");
            return;
        }
        try {
            var claims = tokens.verify(header.substring(BEARER.length()));
            if (claims.isEmpty()) {
                refuse(response, 401, "unauthorized");
            } else if (!groups(claims.get()).contains(group)) {
                refuse(response, 403, "forbidden");
            } else {
                request.setAttribute(ADMINISTRATOR, new Administrator(claims.get().getSubject(), name(claims.get())));
                chain.doFilter(request, response);
            }
        } catch (AccessTokens.Unavailable _) {
            refuse(response, 503, "temporarily_unavailable");
        }
    }

    private static List<String> groups(JWTClaimsSet claims) {
        try {
            var groups = claims.getStringListClaim("groups");
            return groups == null ? List.of() : groups;
        } catch (ParseException _) {
            return List.of();
        }
    }

    private static String name(JWTClaimsSet claims) {
        try {
            return claims.getStringClaim("name");
        } catch (ParseException _) {
            return null;
        }
    }

    private static void refuse(HttpServletResponse response, int status, String error) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + error + "\"}");
    }
}
