package io.security.basicSecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());

        /*
         * SecurityContext의 저장방식 설정이 필요한 경우 작성하게 된다.
         * - `MODE_THREADLOCAL` : 기본 값으로 스레드 당 SecurityContext 객체를 할당하게된다.
         * - `MODE_INHERITABLETHREADLOCAL` : 메인 스레드와 자식 스레드에 관한여 동일한 SecurityContext를 유지하게 된다.
         * - `MODE_GLOBAL` : 응용 프로그램에서 단 하나의 SecurityContext를 저장한다.
         */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        return http.build();
    }
}
