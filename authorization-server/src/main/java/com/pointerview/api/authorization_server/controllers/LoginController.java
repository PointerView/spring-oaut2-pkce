package com.pointerview.api.authorization_server.controllers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

  /* Si se hace uso del fallback propio de spring para el login y logout esto es innecesario pero
  * si se quiere pasar una vista personalizada se debera de indicar en estos controllers*/

  @GetMapping("/login")
  public String login() {
    return "login";
  }

  @GetMapping("/logout")
  public String logout() {
    return "logout";
  }

  @PostMapping("/logout")
  public String logoutOk(HttpSecurity http) throws Exception {
    http.logout(logoutConfig -> {
      logoutConfig.logoutSuccessUrl("llogin?logout")
              .deleteCookies("JSESSIONID")
              .clearAuthentication(true)
              .invalidateHttpSession(true);
    });
    // Redireccion a login con el parametro logout sin valor
    return "login?logout";
  }
  /************************************************************************/
}
