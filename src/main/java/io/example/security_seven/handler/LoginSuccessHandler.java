package io.example.security_seven.handler;

import io.example.security_seven.domain.jwt.service.RefreshService;
import io.example.security_seven.util.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    //
    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    public LoginSuccessHandler(JWTUtil jwtUtil, RefreshService refreshService) {
        this.jwtUtil = jwtUtil;
        this.refreshService = refreshService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String username = authentication.getName();
        // role 첫번째 먼 추출
        String role = authentication.getAuthorities().iterator().next().getAuthority();;
        // 로그인을 성공하면 accessToken 과 refreshToken 을 함께 발행
        String accessToken = jwtUtil.createAccessToken(username, role);
        String refreshToken = jwtUtil.createRefreshToken(username, role);

        // Refresh 토큰은 생명 주기가 아주 길기 때문에 발급시 서버측에서 화이트 리스트 관리를 위한 저장
        // 이후 로그아웃시 화이트 리스트에서 제거하여 탈취된 Refresh로 접근하는 요청 방지에 사용
        refreshService.registerRefreshEntity(username, refreshToken);
        // 응답
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String json = String.format("{\"accessToken\":\"%s\",\"refreshToken\":\"%s\"}", accessToken, refreshToken);
        response.getWriter().write(json);
        response.getWriter().flush();
    }
}
