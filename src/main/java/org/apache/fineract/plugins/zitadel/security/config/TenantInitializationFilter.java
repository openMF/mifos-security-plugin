package org.apache.fineract.plugins.zitadel.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.fineract.infrastructure.core.domain.FineractPlatformTenant;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.core.service.tenant.TenantDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TenantInitializationFilter extends OncePerRequestFilter {

    @Autowired
    private TenantDetailsService tenantDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (ThreadLocalContextUtil.getTenant() == null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                Jwt token = jwtAuth.getToken();
                String tenantIdentifier = token.getClaimAsString("tenantIdentifier");

                if (tenantIdentifier != null) {
                    FineractPlatformTenant tenant = tenantDetailsService.loadTenantById(tenantIdentifier);
                    ThreadLocalContextUtil.setTenant(tenant);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}

