package br.com.auth.client;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import br.com.auth.constant.ParamName;

public class AuthenticationFilter implements Filter {

	private String urlAuthentication;
	private String urlRedirect;
	
	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
        
		boolean hasSession = false;

		Cookie[] cookies = request.getCookies();
		
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(ParamName.SESSION_COOKIE)) {
					try {
						JSONObject jsonObject = new JSONObject(cookie.getValue());
						String userId = jsonObject.get(ParamName.USER_ID).toString();
						
						
						if (!userId.equals("0")) {
							hasSession = true;
							filterChain.doFilter(servletRequest, servletResponse);
						}
					} catch (JSONException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		if (!hasSession)
			response.sendRedirect(urlAuthentication + "?" + ParamName.URL + "=" + urlRedirect);
	}

	public void init(FilterConfig filterConfig) throws ServletException {
		//Get init parameter
		urlAuthentication = filterConfig.getInitParameter("url-authentication");
        urlRedirect = filterConfig.getInitParameter("url-redirect");
	}

}
