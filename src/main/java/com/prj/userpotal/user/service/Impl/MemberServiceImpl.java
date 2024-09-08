package com.prj.userpotal.user.service.Impl;

import com.prj.userpotal.common.utils.JwtTokenProvider;
import com.prj.userpotal.user.entity.Members;
import com.prj.userpotal.user.repo.MemberRepository;
import com.prj.userpotal.user.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.MissingFormatArgumentException;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public void userJoin(Members members) {
        members.setPassword(passwordEncoder.encode(members.getPassword()));
        memberRepository.save(members);
    }

    @Override
    public List<Members> getMembers() {
        return memberRepository.findAll();
    }

    @Override
    public Members getMemberByEmail(String email) {
        return memberRepository.findByEmail(email);
    }

    @Override
    public Members login(Members members, HttpServletRequest request, HttpServletResponse response) {
        // 암호 비교
        // 해더 토큰 유무 체크
        // 해더에 토큰 없으면 생성 있으면 validation 체크
        // validation 체크 true 이면 사용자 email 추출
        // 추출된 이메일로 사용자 정보 조회
        // 로그인 완료
        Members info = memberRepository.findByEmail(members.getEmail());
        if (!passwordEncoder.matches(members.getPassword(), info.getPassword())) {
            throw new RuntimeException("비밀번호가 다릅니다.");
        }

        String token = request.getHeader("Authorization");
        if (ObjectUtils.isEmpty(token)) {
            response.setHeader("Authorization", jwtTokenProvider.createToken(members.getUsername(), listRoleConvert(members.getRole())));
            log.info("token::::: {}", response.getHeader("Authorization"));
            return info;
        } else {
            if (jwtTokenProvider.validateToken(token)) {
                return info;
            } else {
                throw new MissingFormatArgumentException("토큰이 만료 되었습니다.");
            }
        }
    }

    public List<String> listRoleConvert(String roles) {
        String[] roleArray = roles.split(",");
        return new ArrayList<>(Arrays.asList(roleArray));
    }
}
