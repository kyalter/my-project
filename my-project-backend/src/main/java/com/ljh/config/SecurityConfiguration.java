package com.ljh.config;

import com.ljh.entity.RestBean;
import com.ljh.entity.vo.response.AuthorizeVO;
import com.ljh.filter.JwtAuthorizeFilter;
import com.ljh.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private JwtAuthorizeFilter jwtAuthorizeFilter;

    @Bean //不加 @Bean → 安全配置未注册 → Spring Security 使用默认策略 → 所有路径需认证 → 访问 /api/auth/login 返回 401。
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin( conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .failureHandler(this::onAuthenticationFailure)
                        .successHandler(this::onAuthenticationSuccess)
                )
                .logout( conf -> conf
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .exceptionHandling(conf ->conf
                        .authenticationEntryPoint(this::onUnauthorized)
                        .accessDeniedHandler(this::onAccessDeny)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    public void onAccessDeny(HttpServletRequest request,
                             HttpServletResponse response,
                             AccessDeniedException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.forbidden(exception.getMessage()).asJsonString());
    }

    public void onUnauthorized(HttpServletRequest request,
                               HttpServletResponse response,
                               AuthenticationException exception) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
    }

    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        response.setContentType("application/json;charset=UTF-8"); // 设置编码格式
        User user = (User) authentication.getPrincipal();
        String token = jwtUtils.createJwt(user, 1, "何佳宇");
        AuthorizeVO vo = new AuthorizeVO();
        vo.setExpire(jwtUtils.expireTime());
        vo.setRole("");
        vo.setToken(token);
        vo.setUsername("何佳宇");
        response.getWriter().write(RestBean.success(vo).asJsonString());
    }
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
    }
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
    }
}
