package com.dmadev.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.time.LocalDate;
import java.util.Date;
import java.util.Map;


//@EnableWebSecurity(debug = true)
@SpringBootApplication
public class SandboxSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SandboxSecurityApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // обновления в написании FilterChain лямбда в версии 6.1 spring

        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(formLogin->formLogin.loginPage("/login").permitAll())
                .httpBasic(httpBasic -> {
                })
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exceptionHandling -> exceptionHandling.
                        authenticationEntryPoint((request, response, authException) -> {
                            response.sendRedirect("http://localhost:8080/public/sign-in.html");
//                            response.sendRedirect("http://localhost:8080/public/403.html");
                            //                    authException.printStackTrace();
                            //                    response.sendError(HttpStatus.UNAUTHORIZED.value());
                        }))
                .build();
    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        // обновления в написании FilterChain лямбда в версии 6.1 spring
//
//        return httpSecurity.httpBasic(httpBasic -> {
//                })
//                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.requestMatchers("/public/test", "/error").permitAll()
//                        .anyRequest().authenticated()
//                ).build();
//    }

    //способ получения пользовательских данных в функциональном обработчике http запроса
    @Bean
    public RouterFunction<ServerResponse> routerFunction() {
        return RouterFunctions.route().GET("/api/v4/greetings", request -> {
            UserDetails userDetails = getUserDetails(request);
            return ServerResponse.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("greeting", "Hello,%s! Today: %s".formatted(userDetails.getUsername(), LocalDate.now().getDayOfWeek())));
        }).build();
    }

    private static UserDetails getUserDetails(ServerRequest request) {
        return request.principal()
                .map(Authentication.class::cast)
                .map(Authentication::getPrincipal)
                .map(UserDetails.class::cast).orElseThrow();
    }


}
