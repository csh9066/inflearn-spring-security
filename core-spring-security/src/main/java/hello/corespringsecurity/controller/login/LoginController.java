package hello.corespringsecurity.controller.login;

import hello.corespringsecurity.service.AccountContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@AllArgsConstructor
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", defaultValue = "false") Boolean error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model
                        ) {
        if (error) {
            model.addAttribute("error", exception);
        }
        return "/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication beforeAuthentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("before logout authentication ={}", beforeAuthentication);
        if (beforeAuthentication != null) {
            // 세션 없애고 컨텍스트도 비워야 함
            new SecurityContextLogoutHandler().logout(request, response, beforeAuthentication);
        }

        Authentication afterAuthentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("after logout authentication ={}", afterAuthentication);

        return "redirect:/login";
    }

    @GetMapping("/denied")
    public String accessDenied(
            @RequestParam(value = "exception", required = false) String exception,
            Model model
            ) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("authentication={}", authentication);
        log.info("authentication.principal={}", authentication.getPrincipal());
        AccountContext accountContext = (AccountContext) authentication.getPrincipal();
        model.addAttribute("username", accountContext.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }

}
