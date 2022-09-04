package com.example.emos.wx.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IController {
    @RequestMapping("/")
    @ResponseBody
    public String hello() {
        return "hello,world";
    }
}
