package com.prj.userpotal.user.repo;

import com.prj.userpotal.user.entity.Members;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MemberRepository extends JpaRepository<Members, Long> {
    Members findByUsername(String username);
    Members findByEmail(String email);
}
