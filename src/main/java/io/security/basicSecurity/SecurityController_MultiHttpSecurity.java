package io.security.basicSecurity;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class SecurityController {

    /*
     * 기본 인증(MODE_THREADLOCAL) 완료 후 확인하면 index의 authentication와 context는 동일한 값으로 확인된다.
     * 다만, 자식 스레드와는 공유되지 않기 때문에 thread의 authentication는 null값이 된다.
     *
     * SecurityConfig 설정 파일에 객체 저장 방식에 대한 수정사항을 반영하면 결과값을 다르게 얻을 수 있다.
     *   ex) SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
     */
    @GetMapping("/")
    public String index(HttpSession session) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        log.info("Authentication info :: {}", authentication);
        log.info("SecurityContext in session :: {}", context.getAuthentication());

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                        log.info("SubThread Authentication info :: {}", authentication);
                    }
                }
        ).start();

        return "thread";
    }
}
