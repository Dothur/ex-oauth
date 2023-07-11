package com.example.auth.config;

import com.example.auth.jwt.JwtTokenFilter;
import com.example.auth.oauth.OAuth2SuccessHandler;
import com.example.auth.oauth.OAuth2UserServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
public class WebSecurityConfig {
    private final JwtTokenFilter jwtTokenFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2UserServiceImpl oAuth2UserService;

    public WebSecurityConfig(JwtTokenFilter jwtTokenFilter, OAuth2SuccessHandler oAuth2SuccessHandler, OAuth2UserServiceImpl oAuth2UserService) {
        this.jwtTokenFilter = jwtTokenFilter;
        this.oAuth2SuccessHandler = oAuth2SuccessHandler;
        this.oAuth2UserService = oAuth2UserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    )
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authHttp -> authHttp
                        .requestMatchers("/token/**", "/views/**")
                        .permitAll()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/views/login")
                        .successHandler(oAuth2SuccessHandler)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oAuth2UserService)
                        )
                )
                .sessionManagement(
                        sessionManagement -> sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtTokenFilter, AuthorizationFilter.class);


        return http.build();
    }

    // 1. OAuth2SuccessHandler 는 UserDetailsManager 를 필요하게 바뀌었다.
    // 2. UserDetailsManager 는 WebSecurityConfig 에 정의해둔 PasswordEncoder
    //      Bean 객체가 필요했다.
    // 3. WebSecurityConfig 는 OAuth2SuccessHandler 가 필요했다
    // 4. WebSecurityConfig 에서 PasswordEncoder 를 분리했다.
    //    -> UserDetailsManager 는 더이상 WebSecurityConfig 를 필요로 하지 않게된다.
    // 5. Circular Dependency 가 해소된다

//    @Bean
//    // 비밀번호 암호화를 위한 Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
}
