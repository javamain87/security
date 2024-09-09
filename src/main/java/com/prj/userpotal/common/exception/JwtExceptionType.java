package com.prj.userpotal.common.exception;

import lombok.Getter;

@Getter
public enum JwtExceptionType {
    EXPIRED_TOKEN("만료된 토큰입니다."),
    UNSUPPORTED_TOKEN("지원되지 않는 토큰입니다."),
    MALFORMED_TOKEN("잘못된 형식의 토큰입니다."),
    INVALID_SIGNATURE("유효하지 않은 서명입니다."),
    INVALID_TOKEN("유효하지 않은 토큰입니다.");

    private final String message;

    JwtExceptionType(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
