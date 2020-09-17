package org.javaboy.vhr.controller;

import org.javaboy.vhr.model.RespBean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/login")
    public RespBean login() {
        return RespBean.error("尚未登录，请登录！");
    }
}
