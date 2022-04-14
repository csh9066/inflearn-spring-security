package hello.corespringsecurity.security.provider;

import hello.corespringsecurity.security.common.FormWebAuthenticationDetails;
import hello.corespringsecurity.security.token.AjaxAuthenticationToken;
import hello.corespringsecurity.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static java.util.Objects.isNull;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("패스 워드가 일치하지 않습니다.");
        }

//        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
//        String secretKey = details.getSecretKey();
//
//        if (isNull(secretKey) || !"secret".equals(secretKey)) {
//            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
//        }

        return new AjaxAuthenticationToken(accountContext, null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
