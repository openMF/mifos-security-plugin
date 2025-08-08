package org.apache.fineract.plugins.zitadel.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ZitadelSecurityConfig {

    @Autowired
    private TenantInitializationFilter tenantInitializationFilter;


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain zitadelSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(
                        "/fineract-provider/**",
                        "/zitadel-token/**",
                        "/tokenOIDC",
                        "/token",
                        "/auth/**",
                        "/userdetails",
                        "/DTO-token"
                )
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/auth/test",
                                "/zitadel-token/token",
                                "/auth/tokenOIDC",
                                "/auth/token",
                                "/auth/userdetails",
                                "/auth/DTO-token",
                                "/actuator/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())))

                // 🔽 Agrega tu filtro personalizado antes del UsernamePasswordAuthenticationFilter
                .addFilterBefore(tenantInitializationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(List.of("http://localhost:4200"));  // origen de Angular
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowCredentials(true);  // necesario si usas cookies o Authorization headers

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("https://plugin-auth-ofrdfj.us1.zitadel.cloud");
    }
}
