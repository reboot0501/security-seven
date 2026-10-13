package io.example.security_seven.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1")
@Slf4j
public class SampleController {
    //
    @GetMapping("/")
    public String index() {
        //
        return "index";
    }

    @GetMapping("/user")
    public String user() {
        //
        String loginName = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("로그인 사용자 정보 중 getName [{}]", loginName);
        return loginName != null? loginName : "";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }
}
