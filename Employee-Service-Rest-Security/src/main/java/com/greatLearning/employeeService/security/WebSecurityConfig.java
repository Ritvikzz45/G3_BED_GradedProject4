package com.greatLearning.employeeService.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.greatLearning.employeeService.service.UserDetailsServiceImpl;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public UserDetailsService userDetailsService() {
		return new UserDetailsServiceImpl();
	}

//	 @Bean
//	    public HttpSessionStrategy httpSessionStrategy() {
//	        return new HeaderHttpSessionStrategy();
//	    }

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider=new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
		
	}
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests().antMatchers("/api/user", "/api/role").hasAuthority("ADMIN")
				.antMatchers(HttpMethod.POST, "/api/employees").hasAuthority("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/employees").hasAuthority("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/employees//{employeeId}").hasAuthority("ADMIN")
				.antMatchers(HttpMethod.GET,"api/employees/customsort","api/employees/search/{firstName}")
				.hasAnyAuthority("USER","ADMIN")
				// .antMatchers("/api/e","/student/delete").hasAuthority("ADMIN")
				.anyRequest().authenticated().and().httpBasic()
				//.and().formLogin().loginProcessingUrl("/login").successForwardUrl("/api/employees")
				//.permitAll().and().logout().logoutSuccessUrl("/login").permitAll()
				 //permitAll()  .and()  .logout().logoutSuccessUrl("/login").permitAll() //
				// .and() // .exceptionHandling().accessDeniedPage("/student/403")
				.and().cors().and().csrf().disable();
		 
		/*
		 * http.authorizeRequests()
		 * .antMatchers("/api/user","/api/role").hasAnyAuthority("USER","Admin")
		 * .antMatchers(HttpMethod.GET,"/api/employees").hasAnyAuthority("USER","ADMIN")
		 * .antMatchers(HttpMethod.POST,"/api/employees").hasAuthority("ADMIN")
		 * .antMatchers(HttpMethod.PUT,"/api/employees").hasAuthority("ADMIN")
		 * .antMatchers(HttpMethod.DELETE,"/api/employees").hasAuthority("ADMIN")
		 * .anyRequest().authenticated().and().httpBasic()
		 * .and().cors().and().csrf().disable();
		 */
			
		
	}

}
