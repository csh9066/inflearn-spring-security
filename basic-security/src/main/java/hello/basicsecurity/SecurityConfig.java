package hello.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

         // 인증
        // 로그인
        http
                .formLogin() // 폼 로그인 사용하겠따 선언
                .defaultSuccessUrl("/") // 로그인 성공 후 리다이렉트 url
                .failureUrl("/login") // 로그인 실패 url
                .usernameParameter("userId") // http request 유저네임 파라미터 (폼 필드네임)
                .passwordParameter("passwd") // htt request password 패스워드 파라미터 (폼 필드네임)
                .loginProcessingUrl("/login_proc") // 로그인 폼 요청시 보내는 url 기본 login_proc
                .successHandler(new AuthenticationSuccessHandler() { // 커스텀 석세스 헨들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        HttpSessionRequestCache requestCache = new HttpSessionRequestCache(); // 인증 예외 발생시 session에 전에 요청한 request를 저장함
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        log.info("auth={}", authentication);
                        response.sendRedirect(redirectUrl);
                    }
                });

        // 로그아웃
        http.logout()
                .logoutUrl("/logout") // 로그아웃 url - default [post /logout]
                .logoutSuccessUrl("/") // 성공시 리다이렉트
                .addLogoutHandler((request, response, authentication) -> { // 기본 로그아웃 핸들러가 리스트로 여러개 있음 거기에 추가하는거
                    HttpSession session = request.getSession(false);
                    log.info("session attributes={}", session.getAttributeNames());
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> { //  로그아웃 성공시 핸들러
                    log.info("logoutSuccess");
                    response.sendRedirect("/");
                });

        // remberme-me
        /*
        *  rememberme 기능이 활성화가 되면 로그인시 쿠키를 발행 해줌
        *  발행된 쿠키는 토큰 방식의 쿠키임 Authencation 객체를 가지고 있는거 같다
        *  로그인 세션이 만료되었으면 서버에서는 remember 쿠키가 있으면 그 쿠키에 값(토큰)을 복호화 시켜
        *  시큐리티 컨텍스트에 인증 정보를 집어 넣음
        *  jwt refresh token과 같은 역할을 하는거 같음
        * */
        http
                .rememberMe()
                .rememberMeParameter("remember") // default rembmer-me
                .tokenValiditySeconds(3600) // default 14일
                .userDetailsService(userDetailsService); // 필수등록 해야함

        /*
        * AnonymousAuthenticationFilter
        * 시큐리티 내부에서 익명사용자와 인증 사용자를 구분해서 처리하기 위한 용도로 사용함
            *
        * */
        http
                .anonymous();


        http.sessionManagement()
                .maximumSessions(2) // 최대 허용 가능 세션 수, -1로 할수 무제한 로그인 세션 허용, 최대 허용 개수가 넘어가면 가장 빨리 인증한 세션을 만료시킴
                .maxSessionsPreventsLogin(false); // ture로 설정 했을 때 최대 허용 세션의 갯수가 넘어갈시 동시 로그인 차단함, default false
//                .expiredUrl("/expired"); // 세션이 만료된 경우 이동 할 페이지

        http
                .sessionManagement()
//                .sessionFixation().newSession() // 인증시 새로운 새션을 만듬 기존의 사용했던 세션 정보들은 다없어짐
                .sessionFixation().changeSessionId() // 기본 값 인증시 기존 새션은 유지하지만 세션 아이디만 바꿈
                /* 세션 생성 정책
                *   alway - 모든 요청마다 생성
                *   if_required - 스프링 시큐리티가 필요시 생성 (기본 값)
                *   never - 스프링 시큐리티 생성하지 않지만 존재하면 사용
                *   stateless - 스프링 시큐리티가 생성하지도 않고 사용하지도 않음
                * */
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);


        http.sessionManagement();
        

        /*
        *  인가 - 권한 설정
        *  선언
        *  URL과 Method 방식이 있음
        *  - URL은 현재 config에서 하는 방식
        *  - Method는 컨트롤러에다가 @PreAuthorize 사용
        * */
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") // 주의점 /admin/** 가 /admin/pay 보다 먼저 오면 안됨
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        /* 인증/인가 예외*/
        http.exceptionHandling()
                /*
                *   인증 예외 발생시
                * */
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 예외 발생시
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });

        http.csrf();

    }
}
