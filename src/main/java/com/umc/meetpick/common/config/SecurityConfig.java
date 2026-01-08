package com.umc.meetpick.common.config;

import com.umc.meetpick.common.jwt.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    @Value("${front.redirect-url}")
    private String frontRedirectUrl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/login",
                                "/login/error",
                                "/error",
                                "/h2-console/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.GET, "/oauth2/**").permitAll()
                        .anyRequest().permitAll() // 로컬에서 일단 막지 말고 오픈
                )

                // H2 콘솔 쓰면 frameOptions disable 필요
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))

                .oauth2Login(oauth -> oauth
                        .loginPage("/login")
                        .failureHandler((request, response, exception) -> {
                            // ✅ 폴더 추가 없이 여기서 바로 처리
                            response.sendRedirect("/login/error");
                        })
                        .successHandler(this::oauth2Success)
                )

                .logout(logout -> logout.disable());

        return http.build();
    }

    /**
     * ✅ OAuth2 성공 시:
     * 1) 카카오 userInfo에서 id / nickname 꺼내기
     * 2) DB에서 회원 조회/생성
     * 3) JWT 발급
     * 4) 프론트로 redirect (front.redirect-url?token=xxx)
     */
    private void oauth2Success(HttpServletRequest request,
                               HttpServletResponse response,
                               org.springframework.security.core.Authentication authentication) throws IOException, ServletException {

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof org.springframework.security.oauth2.core.user.OAuth2User oauth2User)) {
            response.sendRedirect("/login/error");
            return;
        }

        Map<String, Object> attributes = oauth2User.getAttributes();

        // 카카오는 보통:
        // id: Long
        // properties.nickname 또는 kakao_account.profile.nickname 에 들어있음
        Long kakaoId = null;
        String nickname = null;

        Object idObj = attributes.get("id");
        if (idObj instanceof Number n) kakaoId = n.longValue();

        Object propsObj = attributes.get("properties");
        if (propsObj instanceof Map<?, ?> props) {
            Object nickObj = props.get("nickname");
            if (nickObj != null) nickname = String.valueOf(nickObj);
        }

        Object accountObj = attributes.get("kakao_account");
        if (nickname == null && accountObj instanceof Map<?, ?> acc) {
            Object profileObj = acc.get("profile");
            if (profileObj instanceof Map<?, ?> profile) {
                Object nickObj = profile.get("nickname");
                if (nickObj != null) nickname = String.valueOf(nickObj);
            }
        }

        if (kakaoId == null) {
            response.sendRedirect("/login/error");
            return;
        }

        // =========================
        // ✅ 여기만 너희 프로젝트 서비스명에 맞게 변경 필요
        // "kakaoId로 memberId 가져오기" 로직
        // =========================

        // 예시:
        // Long memberId = memberService.findOrCreateByKakao(kakaoId, nickname);

        // ⚠️ 프로젝트에 서비스가 없을 수 있으니,
        // 일단 "kakaoId 자체를 memberId처럼" 임시로 발급해서 프론트 테스트는 가능하게 해둠
        Long memberId = kakaoId; // 임시

        String token = jwtUtil.generateToken(memberId);

        String redirect = frontRedirectUrl
                + (frontRedirectUrl.contains("?") ? "&" : "?")
                + "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

        response.sendRedirect(redirect);
    }
}
