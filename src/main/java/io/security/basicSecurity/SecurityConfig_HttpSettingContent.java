package io.security.basicSecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

import static org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.*;

/**
 * Spring Security에서 제공하는 http 설정 사용방법에 대한 기록
 */
@Configuration
@EnableWebSecurity  // @EnableWebSecurity 를 기입해야 웹 보한이 활성화된다.
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS", "USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();
        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //http.authorizeHttpRequests(authz -> authz
                /*
                 * 요청에 대한 인증 범위를 설정하게된다.
                 * .anyRequest() : 모든 요청을 설정하기 위함
                 * .authenticated() : 인증이 필요함을 의미
                 */
                //.anyRequest().authenticated()
        //);

        //http.securityMatcher("/shop/**").authorizeHttpRequests(authorize -> authorize
        http.authorizeHttpRequests(authorize -> authorize
                /*
                 * 요청에 대한 인증 범위를 설정하게된다.
                 * - permitAll - The request requires no authorization and is a public endpoint; note that in this case, the Authentication is never retrieved from the session
                 * - denyAll - The request is not allowed under any circumstances; note that in this case, the Authentication is never retrieved from the session
                 * - hasAuthority - The request requires that the Authentication have a GrantedAuthority that matches the given value
                 * - hasRole - A shortcut for hasAuthority that prefixes ROLE_ or whatever is configured as the default prefix
                 * - hasAnyAuthority - The request requires that the Authentication have a GrantedAuthority that matches any of the given values
                 * - hasAnyRole - A shortcut for hasAnyAuthority that prefixes ROLE_ or whatever is configured as the default prefix
                 * - access - The request uses this custom AuthorizationManager to determine access

                .requestMatchers("/shop/login", "/shop/users/**").permitAll()
                .requestMatchers("/shop/mypage").hasRole("USER")
                // 아래 /shop/admin 하위 경로 설정과 같은 경우 선언 순서를 지켜야된다. 작은 범위의 경로부터 큰 범위의 경로로 넓히면서 권한을 부여한다.
                .requestMatchers("/shop/admin/pay").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasIpAddress('192.168.1.0/24')"))
                .requestMatchers("/shop/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                .anyRequest().authenticated()
                 */
                .requestMatchers("/login").permitAll()
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/admin/pay").hasRole("ADMIN")
                .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                .anyRequest().authenticated()
        );

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                /*
                 * 인증 인가로 인한 문제 발생
                 */
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        );

        http.formLogin(form -> form
                /*
                 * Login 시 form 형태로 요청이 발생한 경우만 허용한다.
                */
                //http.formLogin(AbstractAuthenticationFilterConfigurer::permitAll);
                //.loginPage("/loginPage")  // 사용자 정의 로그인 페이지 설정한다.
                .defaultSuccessUrl("/")  // 로그인 성공 후 이동 URL을 의미한다.
                .failureUrl("/login")  // 로그인 실패 후 이동 URL을 의미한다.
                .usernameParameter("userId")  // 아이디 파라미터명 설정한다.
                .passwordParameter("passwd")  // 패스워드 파라미터명 설정한다.
                .loginProcessingUrl("/login_proc")  // 로그인 Form Action Url이다.
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication : " + authentication.getName());

                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();

                        response.sendRedirect(redirectUrl);
                    }
                })  // 로그아웃 처리 성공 후 추가 요건이 존재하면 Handler로 구현하여 적용할 수 있도록 기능을 제공한다.
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("Exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })  // 로그아웃 처리 실패 후 추가 요건이 존재하면 Handler로 구현하여 적용할 수 있도록 기능을 제공한다.
        );

        http.rememberMe(remember -> remember
                /*
                 * 브라우져 종료 또는 만료 시간으로 인한 로그인 단절을 보완하기 위한 방법으로 Remember-Me 기능을 제공한다.
                 * Remember-Me는 Session이 끊어져도 Client에서 유효한 Remember-Me 값을 보내오면 서버에 저장된 정보와 일치하면 해당 계정의 인증을 수행한다.
                 *
                 * [서버에 Remember-Me 정보를 저장하는 방법]
                 * - TokenBasedRememberMeServices : 서버의 로컬 메모리에 저장하는 방식으로 제공한다.
                 * - PersistentTokenBasedRememberMeServices : 데이터베이스에 저장하는 방식으로 제공한다.
                 */
                .rememberMeParameter("remember") // Remember me의 파라미터 명을 설정하는 api입니다. default 값은 remember-me이다
                .tokenValiditySeconds(3600)  // 만료 시간 설정할 수 있다. (Default : 14일)
                .alwaysRemember(true)  // Remember-Me 기능이 활성화 되지 않아도 항상 실행을 의미한다.
                //.userDetailsService(userDetailsService) // Spring Security에서 유저의 정보를 가져오는 인터페이스이다.
                .userDetailsService(users())
        );

        http.sessionManagement(session -> session
                /*
                 * 동시 세션 제어
                 * 1. 이전 사용자 Session 만료
                 * 2. 현재 사용자 인증 실패
                 */
                .invalidSessionUrl("/invalidSession")  // 세션이 유효하지 않을 때 이동할 페이지
                /*
                 * 세션 고정 공격을 방어하기 위해 사용자의 요청마다 세션을 신규로 생성하는 방식을 취한다.
                 */
                //.sessionFixation().migrateSession()
                .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::newSession)
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)  // 동일한 계정으로 로그인 가능 최대 개수, -1인 경우 무제한 로그인 세션을 허용한다.
                .maxSessionsPreventsLogin(true)  // true 동시 로그인 차단, false 기존 세션 만료(default)
                .expiredUrl("/login")  // 세션이 만료된 경우 이동할 페이지
        );

        http.logout(logout -> logout
                .logoutUrl("/logout")  // 로그아웃 처리할 URL
                .logoutSuccessUrl("/login")  // 로그아웃 처리 후 이동할 페이지 URL
                .deleteCookies("JSESSIONID", "remember-me")  // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(
                        new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.COOKIES))
                )  // 기본적으로 Handler에서 세션 무효화, 인증토큰 삭제 등 처리 외에 처리하고 싶은 사항을 Handler로 구현하여 적용할 수 있도록 기능을 제공한다.
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })  // 로그아웃 처리 완료 후 추가 요건이 존재하면 Handler로 구현하여 적용할 수 있도록 기능을 제공한다.
        );

        return http.build();
    }

    @Bean
    RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
        RememberMeTokenAlgorithm encodingAlgorithm = RememberMeTokenAlgorithm.SHA256;
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices("myKey", userDetailsService, encodingAlgorithm);
        rememberMe.setMatchingAlgorithm(RememberMeTokenAlgorithm.MD5);
        return rememberMe;
    }
}
