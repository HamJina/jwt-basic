package com.example.SpringJWT.config;


import com.example.SpringJWT.jwt.JWTFilter;
import com.example.SpringJWT.jwt.JWTUtil;
import com.example.SpringJWT.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration //스프링부트에서 관리되기 위함
@EnableWebSecurity //시큐리티를 위한 config
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguration 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    //JWTUtil주입
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configurations) throws Exception {
        return configurations.getAuthenticationManager();
    }

    //비밀번호를 해시로 암호화 시켜서 검증
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean //인가 작업, 로그인 방식 설정, 세션 설정
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));
        //csrf disable(jwt)
        http
                .csrf((auth) -> auth.disable());
        //From 로그인 방식 disable(jwt)
        http
                .formLogin((auth) -> auth.disable());
        //http basic 인증 방식 disable(jwt)
        http
                .httpBasic((auth) -> auth.disable());
        //특정 경로에 대해 어떤 권한을 가져야 하는지 (인가작업)
        http
                .authorizeHttpRequests((auth) -> auth
                        //해당 경로에 대해서는 모든 권한 허용
                        .requestMatchers("/login", "/", "/join").permitAll()
                        //해당 경로는 admin이라는 권한을 가진 사람만 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN")
                        //다른 요청에 대해서는 로그인한 사용자만 접근할 수 있다.
                        .anyRequest().authenticated());
        //JWTFilter등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
        //jwt방식에서는 세션을 stateless상태(무상태)로 관리 (중요!!!!)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
