package com.ljh.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.xml.crypto.Data;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    private String key; // 进行jwt令牌加密的密钥

    @Value("${spring.security.jwt.expire}")
    private int expire; //设置的jwt过期时间

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    public boolean invalidateJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token != null) return false;
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(key)).build();
        try {
            DecodedJWT jwt = jwtVerifier.verify(token);
            String id = jwt.getId();
            return deleteToken(id,jwt.getExpiresAt());
        }catch (JWTVerificationException e){
            return false;
        }
    }

    private boolean deleteToken(String uuid, Date time){
        if(this.isInvalidToken(uuid)) return false;
        Date now = new Date();
        long expire = Math.max(time.getTime() - now.getTime(),0);
        stringRedisTemplate.opsForValue().set(Const.JWT_BLACK_LIST+uuid,"",expire, TimeUnit.MICROSECONDS);
        return true;
    }

    // 查询当前jwt的uuid是否在redis的黑名单列表当中 是否失效
    private boolean isInvalidToken(String uuid){
        return stringRedisTemplate.hasKey(Const.JWT_BLACK_LIST + uuid);
    }

    public DecodedJWT resolveJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(key)).build(); // 进行jwt令牌的解析校验
        try {
            DecodedJWT verify = jwtVerifier.verify(token); //验证令牌是否被修改
            if(this.isInvalidToken(verify.getId()))
                return null;
            Date expiresAt = verify.getExpiresAt(); // 获取令牌过期日期
            return new Date().after(expiresAt) ? null : verify;
        } catch (JWTVerificationException e) {
            return null;
        }

    }
    public String createJwt(UserDetails details , int id , String username){
        Date expireDate = expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
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
