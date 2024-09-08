package com.prj.userpotal.user.controller;

import com.prj.userpotal.user.entity.Members;
import com.prj.userpotal.user.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/join")
    public void join(@RequestBody Members members) {
        memberService.userJoin(members);
    }

    @PostMapping("/login")
    public void login(@RequestBody Members members, HttpServletRequest request, HttpServletResponse response) {
        memberService.login(members,request,response);
    }
}
