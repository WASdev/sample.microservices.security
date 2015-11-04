package net.wasdev.securemicroservices.common;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;

/**
 * A shared class for generating and validating API keys.
 * 
 * Copyright 2015 IBM Corp.
 */
public class APIKey implements Filter, ClientRequestFilter {
	public static final String SYSPROP_LOGGING = "apikey.log";	//system property to let you see what is going on
	private static final String CHAR_SET = "UTF-8";
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final ConcurrentMap<String, Long> usedKeys = 
			new ConcurrentHashMap<String, Long>();	//keys already received, prevent replay attacks
	private String serviceID = null;	//this is the ID of the service making the API call
	private String syspropName = null;	//the system property or environment variable which contains the shared secret
	private long timeoutMS = 5000;		//timeout for requests, default to 5 seconds
	
	
	//ensure consistent parameter names
	public enum Params {
		apikey,
		serviceID,
		stamp;
		
		public String toString() {
			return "&" + this.name() + "=";
		}
		
	}

	//default no args constructor for when acting as a filter
	public APIKey() {}
	
	/**
	 * Constructor to be used by the client.
	 * 
	 * @param serviceID the ID representing this service.
	 * @param syspropName the system property or env var which contains the shared secret to use when invoking the remote API.
	 */
	public APIKey(String serviceID, String syspropName) {
		this.serviceID = serviceID;
		this.syspropName = syspropName;
	}
	
	//the authentication steps that are performed on an incoming request
	private enum AuthenticationState {
		hasQueryString,			//starting state
		hasAPIKeyParam,
		isAPIKeyValid,
		hasKeyExpired,
		checkReplay,
		PASSED,					//end state
		ACCESS_DENIED			//end state
	}

	/**
	 * Handles incoming API calls from clients and validates them.
	 * 
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		String queryString = null; String apikey = null;
		int pos = 0; long time = 0;
		AuthenticationState state = AuthenticationState.hasQueryString;		//default
		while(!state.equals(AuthenticationState.PASSED)) {
			switch(state) {
				case hasQueryString :	//check that there is a query string which will contain the service ID and api key
					queryString = ((HttpServletRequest) request).getQueryString();	//this is the raw version
					state = (queryString == null) ? AuthenticationState.ACCESS_DENIED : AuthenticationState.hasAPIKeyParam;
					break;
				case hasAPIKeyParam :	//check there is an apikey parameter
					pos = queryString.lastIndexOf(Params.apikey.toString());
					state = (pos == -1) ? AuthenticationState.ACCESS_DENIED : AuthenticationState.isAPIKeyValid;
					break;
				case isAPIKeyValid :	//validate API key against all parameters (except the API key itself)
					queryString = queryString.substring(0, pos);	//remove API key from end of query string
					String hmac = request.getParameter(Params.apikey.name());
					apikey = digest(queryString);
					state = !apikey.equals(hmac) ? AuthenticationState.ACCESS_DENIED : AuthenticationState.hasKeyExpired;
					break;
				case hasKeyExpired :	//check that key has not timed out
					time = Long.parseLong(request.getParameter(Params.stamp.name()));
					state = (System.currentTimeMillis() - time) > timeoutMS ? AuthenticationState.ACCESS_DENIED : AuthenticationState.checkReplay;
					break;
				case checkReplay : //simple replay check - only allows the one time use of API keys, storing time allows expired keys to be purged
					Long value = usedKeys.putIfAbsent(apikey, time);
					state = value != null ? AuthenticationState.ACCESS_DENIED : AuthenticationState.PASSED;
					break;
				case ACCESS_DENIED :
				default :
					((HttpServletResponse)response).sendError(HttpServletResponse.SC_FORBIDDEN);
					return;
			}
		}
		//request has passed all validation checks, so allow it to proceed
		request.setAttribute(Params.serviceID.name(), request.getParameter(Params.serviceID.name()));
		chain.doFilter(request, response);
	}



	/* 
	 * Entry point for the client that wants to make a request to a second 
	 * service. It takes the original URI supplied and adds additional query string
	 * parameters. These are 
	 * 
	 * 1. The service ID supplied by the client
	 * 2. A timestamp of when the request was made
	 * 3. A generated API key for this invocation.
	 * 
	 * @see javax.ws.rs.client.ClientRequestFilter#filter(javax.ws.rs.client.ClientRequestContext)
	 */
	@Override
	public void filter(ClientRequestContext ctx) throws IOException {
		String idparams = Params.serviceID.toString() + serviceID + Params.stamp.toString() + Long.toString(System.currentTimeMillis());
		String apikey = ctx.getUri().getRawQuery() + idparams;
		String hmac = URLEncoder.encode(digest(apikey), CHAR_SET);
		URI uri = URI.create(ctx.getUri().toString() + idparams + Params.apikey.toString() + hmac);
		System.setProperty(SYSPROP_LOGGING, "Outgoing request url : " + uri.toString());
		ctx.setUri(uri);
	}

	/*
	 * Construct a HMAC for this request.
	 * It is then base 64 and URL encoded ready for transmission as a query parameter.
	 */
	private String digest(String message) throws IOException {
		try {
			byte[] data = message.getBytes(CHAR_SET);
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			SecretKeySpec key = getKey();
			mac.init(key);
			return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data));
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
	
	/*
	 * Gets the secret key from either a system property or environment variable.
	 * The system property takes precedence over the environment variable.
	 */
	private SecretKeySpec getKey() throws IOException {
		String secret = System.getProperty(syspropName, System.getenv(syspropName));
		if((secret == null) || secret.isEmpty()) {
			throw new IOException("The variable " + syspropName + " is not valid");
		}
		return new SecretKeySpec(secret.getBytes(CHAR_SET), HMAC_ALGORITHM);
	}
	
	/**
	 * Read configuration from web.xml
	 * 
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
		syspropName = fConfig.getInitParameter("secretVarName");
		String value = fConfig.getInitParameter("timeOutMs");
		if(value != null) {
			timeoutMS = Long.parseLong(value);
		}
	}
	
	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
		// do nothing
	}
}
