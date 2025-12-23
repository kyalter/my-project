package com.ljh.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.xml.crypto.Data;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    private String key; // 进行jwt令牌加密的密钥

    @Value("${spring.security.jwt.expire}")
    private int expire; //设置的jwt过期时间

    public DecodedJWT resolveJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(key)).build(); // 进行jwt令牌的解析校验
        try {
            DecodedJWT verify = jwtVerifier.verify(token); //验证令牌是否被修改
            Date expiresAt = verify.getExpiresAt(); // 获取令牌过期日期
            return new Date().after(expiresAt) ? null : verify;
        } catch (JWTVerificationException e) {
            return null;
        }

    }
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

    public UserDetails toUser(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        return User
                .withUsername(claims.get("username").asString())
                .password("*********")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public Integer toId(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    private String convertToken(String headerToken){
        if (headerToken == null || !headerToken.startsWith("Bearer "))
            return null;
        return headerToken.substring(7);
    }
}
