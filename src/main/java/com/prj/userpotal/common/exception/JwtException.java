package com.prj.userpotal.common.exception;

import lombok.Getter;

public class JwtException extends RuntimeException {

    private final JwtExceptionType type;

    public JwtException(JwtExceptionType type) {
        super(type.getMessage());
        this.type = type;
    }

    public JwtExceptionType getType() {
        return type;
    }

}
