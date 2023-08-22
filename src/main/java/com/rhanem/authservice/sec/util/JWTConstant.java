package com.rhanem.authservice.sec.util;

public class JWTConstant {

    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEADER = "Authorization";
    public static final long EXPIRE_ACCESS_TOKEN = 2*60*1000;
}
