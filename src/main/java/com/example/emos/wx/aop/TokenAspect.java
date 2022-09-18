package com.example.emos.wx.aop;

import com.example.emos.wx.common.util.R;
import com.example.emos.wx.config.shiro.TokenThreadLocal;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class TokenAspect {

    @Autowired
    private TokenThreadLocal local;

    @Pointcut("execution(public * com.example.emos.wx.controller.*.*(..)))")
    public void pointCut() {

    }

    @Around("pointCut()")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        R r = (R) point.proceed();
        String token = local.getToken();
        if (token != null) {
            r.put("token", token);
            local.clear();
        }
        return r;
    }
}
