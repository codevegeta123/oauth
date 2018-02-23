package com.exp.controller;

/**
 * Created by rohith on 17/2/18.
 */

import org.springframework.web.bind.annotation.RestController;
import com.exp.domain.User;
import com.exp.repository.UserRepository;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RestController
//@RequestMapping("/secure")
public class UserController {
	
	@Autowired
	private UserRepository userRepository;
	

    @GetMapping("/user")
    public @ResponseBody Map<String, String> getUser() {
        return getSuccessResponse();
    }

    @GetMapping("/admin")
    public @ResponseBody Map<String, String> getAdmin() {
        return getSuccessResponse();
    }

    @PreAuthorize("hasRole('PARTICIPANT')")
    @GetMapping("/participant")
    public @ResponseBody Map<String, String> getParticipant() {
        return getSuccessResponse();
    }
    
    @SuppressWarnings("unchecked")
	@GetMapping("/user/profile")
    public ResponseEntity<Map> fetchUserDetails() {
    	
    	User user = getUserDetails();
    	Map resultMap = new HashMap<>();
    	
    	resultMap.put("user_id", user.getId());
    	resultMap.put("username", user.getUsername());
    	resultMap.put("email", user.getEmail());
    	resultMap.put("phone", user.getPhoneNumber());
    	resultMap.put("fullname", user.getName());
    	resultMap.put("first_name", user.getName());
    	resultMap.put("last_name", user.getName());
    	
    	return new ResponseEntity<Map>(resultMap, HttpStatus.OK);
    }


    private Set<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toSet());
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
    
    private User getUserDetails(){
    	
    	Authentication currentAuthentication =  getAuthentication();
    	String username = currentAuthentication.getName();
    	User user = userRepository.findByUsername(username);
    	
    	return user;
    }

    private Map<String, String> getSuccessResponse() {
        Authentication authentication = getAuthentication();
        Set<String> roles = getRoles(authentication);
        Map<String, String> response = new HashMap<>();
        response.put("username", authentication.getName());
        response.put("role", roles.toString());
        response.put("message", "success");
        return response;
    }
}

