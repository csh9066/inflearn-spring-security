package hello.corespringsecurity.controller.user;

import hello.corespringsecurity.domain.Account;
import hello.corespringsecurity.dto.AccountDto;
import hello.corespringsecurity.service.AccountService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@AllArgsConstructor
@Controller
public class AccountController {

    private AccountService accountService;

    @GetMapping(value = "/mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("/accounts")
    public String createUserForm() {
        return "user/login/register";
    }

    @PostMapping("/accounts")
    public String createUser(AccountDto accountDto) {
        log.info("accountdto={}", accountDto);
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        accountService.createAccount(account);
        return "redirect:/";
    }

}
