package io.example.security_seven.api;

import io.example.security_seven.domain.user.entity.UserRequestDTO;
import io.example.security_seven.domain.user.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1")
public class JoinController {
    //
    private final UserService userService;

    public JoinController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/join")
    public String join(@RequestBody UserRequestDTO dto) {
        //
        userService.join(dto);
        return "ok";
    }
}
