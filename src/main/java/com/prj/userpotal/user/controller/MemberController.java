package com.prj.userpotal.user.controller;

import com.prj.userpotal.common.utils.JwtTokenProvider;
import com.prj.userpotal.user.entity.Members;
import com.prj.userpotal.user.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/join")
    public void join(@RequestBody Members members) {
        memberService.userJoin(members);
    }

    @PostMapping("/login")
    public Members login(@RequestBody Members members, HttpServletRequest request, HttpServletResponse response) {
        Members result = memberService.login(members,request,response);
        return result;
    }

    @PostMapping("/valid")
    public ResponseEntity<Boolean> valid(@RequestAttribute String token) {
        return ResponseEntity.ok(jwtTokenProvider.validateToken(token));
    }
}
