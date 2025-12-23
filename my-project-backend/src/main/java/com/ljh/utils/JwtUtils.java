package com.ljh.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.xml.crypto.Data;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    private String key; // 进行jwt令牌加密的密钥

    @Value("${spring.security.jwt.expire}")
    private int expire; //设置的jwt过期时间

    public String createJwt(UserDetails details , int id , String username){
        Date expireDate = expireTime();
        return JWT.create()
                .withClaim("id",id)
                .withClaim("username",username)  //Jwt令牌的payload载荷部分
                .withClaim("authorities",details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expireDate)  //设置过期时间
                .withIssuedAt(new Date())  //设置签发时间
                .sign(Algorithm.HMAC256(key));  //进行HMAC256加密
    }
    public Date expireTime(){
        return new Date(new Date().getTime()+expire);
    }
}
