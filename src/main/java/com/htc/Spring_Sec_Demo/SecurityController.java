package com.htc.Spring_Sec_Demo;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class SecurityController {
	
	
	@GetMapping("hello")
	public String greet(HttpServletRequest request) {
		
		return "Hello World!! " + request.getSession().getId();
	}
	
	@GetMapping("about")
	public String about(HttpServletRequest request) {
		return "Telusko "+ request.getSession().getId();
	}

}
