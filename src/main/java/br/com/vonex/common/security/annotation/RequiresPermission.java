package br.com.vonex.common.security.annotation;

import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresPermission {
    String[] value();
    boolean requireAll() default false;
    String message() default "Acesso negado: permissão insuficiente";
}