package io.example.security_seven.config;

import io.example.security_seven.filter.JWTFilter;
import io.example.security_seven.filter.LoginFilter;
import io.example.security_seven.handler.LoginSuccessHandler;
import io.example.security_seven.util.JWTUtil;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** SecurityConfig :  Security 필터를 통제하고 커스텀
 *  시큐리티 필터 부분을 통제할 수 있는 Bean을 등록해서 로그인, JWT 검증 필터를 추가할 수 있도록 설정
 *  (시큐리티 필터 부분은 여러개의 필터로 이루어짐 : 보안관리, 로그인, 로그아웃, 세션관리, 인가, 등)
 */
@Configuration
public class SecurityConfig {
    //
    private final AuthenticationConfiguration authenticationConfiguration;
    private final LoginSuccessHandler loginSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(
            AuthenticationConfiguration authenticationConfiguration,
            LoginSuccessHandler loginSuccessHandler,
            JWTUtil jwtUtil
    ) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    /**
     * AuthenticationManager Bean 등록
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) {
        //
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 프론트 엔드 서버의 URL 오리진이 틀릴 경우
     * @return
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.addAllowedOrigin("http://localhost:5173");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    /** securityFilterChain
     * CSRF 필터를 disable, 경로별 인가, 로그인, JWT 검증, 인가
     * @param httpSecurity
     * @return
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) {
        // 수많은 필터 중 CSRF 필터를 disable 시킴 ( 세션관리가 State less 함으로 CSRF 필터 불필요 )
        // CSRF(Cross-Site Request Forgery, 사이트 간 요청 위조) 는
        // 사용자가 정상적으로 로그인한 웹사이트에서,
        // 공격자가 사용자의 권한을 이용해 원하지 않는 요청을 실행하도록 유도하는 공격
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable);
        // 경로별 인가
        // 전체 경로 인가 : auth.requestMatchers("/**").permitAll())
        httpSecurity
                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers("/api/v1/join").permitAll()
                                .requestMatchers("/api/v1/jwt/refresh").permitAll()
                                .requestMatchers("/api/v1/").permitAll()
                                .requestMatchers("/api/v1/user").hasRole("USER")
                                .anyRequest().hasRole("ADMIN")
                );
        // Session 설정 State Less 하게 (서버과 사용자 정보를 기억하지 않아도 되도록 처리)
        httpSecurity
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // 기본 로그인 disable 시키고 커스텀 로그인 필터 작성 必
        httpSecurity
                .formLogin(AbstractHttpConfigurer::disable);

        // 커스텀 로그인 필터 등록
        httpSecurity
                .addFilterBefore(
                        new LoginFilter(authenticationManager(authenticationConfiguration), loginSuccessHandler),
                        UsernamePasswordAuthenticationFilter.class
                );
        // JWT body 추출
        httpSecurity
                .addFilterAfter(new JWTFilter(jwtUtil), SecurityContextHolderFilter.class);

        // 세션 설정 STATELESS
        httpSecurity
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );


        return httpSecurity.build();
    }

    /**
     * 회원가입시 비밀번호 암호화, 로그인시 입력 비밀번호 Hash 화
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
