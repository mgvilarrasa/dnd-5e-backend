package com.mgv.dnd.test_jwt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/testing")
public class HomeController {

    private final UserService userService;

    public HomeController(
            UserService userService
    ) {
        this.userService = userService;
    }

    @GetMapping("/home")
    public String home() {
        return "Hello!";
    }


    @PostMapping("/user")
    public String user(
            @RequestParam() String name,
            @RequestParam() String surname,
            @RequestParam() String email,
            @RequestParam() String password
    ) {
        this.userService.createUser(name, surname, email, password);
        return "Jeje";
    }
}