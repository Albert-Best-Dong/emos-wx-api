package com.example.emos.wx.exception;

import lombok.Data;

@Data
public class EmosException extends RuntimeException {
    private int code = 500;
    private String msg;

    public EmosException(String msg) {
        super(msg);
        this.msg = msg;
    }
    public EmosException(int code,Throwable cause) {
        super(cause);
        this.code = code;
    }
    public EmosException(int code, String msg) {
        super(msg);
        this.code = code;
        this.msg = msg;
    }

    public EmosException(Throwable cause, int code, String msg) {
        super(msg, cause);
        this.code = code;
        this.msg = msg;
    }
}
