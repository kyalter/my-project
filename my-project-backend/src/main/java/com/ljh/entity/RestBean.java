package com.ljh.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

public record RestBean<T>(int code, String message, T data) {
    public static <T> RestBean<T> success(T data) {
        return new RestBean<>(200,"请求成功", data);
    }
    public static <T> RestBean<T> success() {
        return success(null);
    }

    public static <T> RestBean<T> failure(int code, String message) {
        return new RestBean<>(code, message, null);
    }

    public String asJsonString() {
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
