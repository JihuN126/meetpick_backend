package com.umc.meetpick.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class LoginController {

    /**
     * ✅ 뷰 리졸버 없이도 확실하게 redirect 되게 sendRedirect 사용
     */
    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/kakao");
    }

    @GetMapping("/login/error")
    public String loginError() {
        return "OAuth2 Login Failed. Check server logs for details.";
    }

    @GetMapping("/")
    public String root() {
        return "OK";
    }
}
