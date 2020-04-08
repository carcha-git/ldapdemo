package com.santander.controller;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;




@CrossOrigin
@RestController
public class LdapController {
	

	@PostMapping(path = "/ldap/authorization")
	public ResponseEntity<?> authorizePost(@RequestParam String user, @RequestParam String pass) {
		//byte[] assetData = Base64.getDecoder().decode(asset.getAssetData());

		if(validateLdapUser(user, pass))
		   return ResponseEntity.ok().build();
		return ResponseEntity.unprocessableEntity().build();
	}
	
	
	@GetMapping(path = "/ldap/authorization")
	public ResponseEntity<?> authorizeGet(@RequestParam String user, @RequestParam String pass) {
		//byte[] assetData = Base64.getDecoder().decode(asset.getAssetData());

		if(validateLdapUser(user, pass))
			return ResponseEntity.ok().build();
        return ResponseEntity.unprocessableEntity().build();
	}
		
	
	/**
	 * user = ro_admin
	 * pass = zflexpass
	 * */
	private boolean validateLdapUser(String user, String pass) {
	    Hashtable<String, String> env = new Hashtable<String, String>(11);
	    boolean b = false;
	    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
	    env.put(Context.PROVIDER_URL, "ldap://www.zflexldap.com:389");
	    env.put(Context.SECURITY_AUTHENTICATION, "simple");
	    env.put(Context.SECURITY_PRINCIPAL, "cn=" + user + ",ou=sysadmins,dc=zflexsoftware,dc=com");
	    env.put(Context.SECURITY_CREDENTIALS, pass);
	    
	    try {
	       // Create initial context
	       DirContext ctx = new InitialDirContext(env);
      
	       
	       // Close the context when we're done
	       b = true;
	       ctx.close();
	    } catch (NamingException e) {
	       b = false;
	    }finally{
	       if(b){
	          System.out.print("Success");
	       }else{
	        System.out.print("Failure");
	       }
	    }
	    return b;
    }
	
	
	
	
}
