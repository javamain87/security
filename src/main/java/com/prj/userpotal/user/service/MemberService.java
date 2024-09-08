package com.prj.userpotal.user.service;

import com.prj.userpotal.user.entity.Members;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;

public interface MemberService {
    void userJoin(Members members);
    List<Members> getMembers();
    Members getMemberByEmail(String email);
    Members login(Members members, HttpServletRequest request, HttpServletResponse response);
}
