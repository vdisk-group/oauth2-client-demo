package org.vdisk.oauth2.demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author vdisk <vdisk@foxmail.com>
 * @version 1.0
 * @date 2021-06-15 16:59
 */
@RequestMapping("/echo")
@RestController
public class EchoController {

    @GetMapping("/text/{value}")
    public String text(@PathVariable String value) {
        return value;
    }

    @GetMapping("/authentication")
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }
}
