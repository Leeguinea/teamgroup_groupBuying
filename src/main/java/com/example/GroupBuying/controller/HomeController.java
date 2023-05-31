package com.example.GroupBuying.controller;

import com.example.GroupBuying.GroupBuyingApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    //기본 페이지 요청 메소드
    @GetMapping("/")
    public String index() {
        return "home"; // templates 폴더의 basic.html 을 찾아감
    }

    @GetMapping("GroupBuying/home")
    public String homeForm(){
        return "home";
    }

    @GetMapping("GroupBuying/notice")
    public String noticeForm(){
        return "notice";    //로그인 시
    }

    @GetMapping("notice")
    public String notice1Form() {
        return "notice";   //로그아웃 시
    }

    @GetMapping("GroupBuying/gesizak")
    public String gesizakForm(){
        return "gesizak";
    }

    @GetMapping("GroupBuying/gesi")
    public String gesiForm(){
        return "gesi";
    }
}
