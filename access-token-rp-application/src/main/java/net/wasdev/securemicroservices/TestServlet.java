package net.wasdev.securemicroservices;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.io.BufferedReader;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.Hashtable;
import java.util.Set;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.security.auth.Subject;
import com.ibm.websphere.security.auth.WSSubject;
import com.ibm.websphere.security.WSSecurityException;

@WebServlet("/Test")
public class TestServlet extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		PrintWriter out = response.getWriter();
		out.println("<html><body><h2>RP Access Token App</h2><br>");

	  //we were authenticated using OIDC, and we want to obtain the access_token that's part of this session.
		Subject s;
		try{
		 	s = WSSubject.getRunAsSubject();
		}catch( WSSecurityException e){
		 	throw new IOException(e);
		}
	  Set<Hashtable> privateHashtableCreds = s.getPrivateCredentials(Hashtable.class);

		//there could be many.. we'll just take the one with access_token.
		Hashtable theChosenOne = null;
		for(Hashtable test : privateHashtableCreds){
		 if(test.containsKey("access_token")){
		   theChosenOne = test;
		 }
		}

		//now we have found the credentials holding the current access_token
		//we will cache it locally so we can invoke the RS with it.
		String access_token = theChosenOne.get("access_token").toString();
		String token_type = theChosenOne.get("token_type").toString();

		//dump the info for reference to the browser.
		out.println("Access Token was : "+access_token+"<br>");
		out.println("Invoking RS with token.. ");

		//invoke the RS app, passing the access token as a get parameter
    String line,buffer="";
		URL rsurl = new URL("https://127.0.0.1:9402/access-token-rs-application/Test?token="+access_token);
		HttpURLConnection conn = (HttpURLConnection)rsurl.openConnection();
		conn.setRequestMethod("GET");

		//read back the response from the RS app.
    int responseCode = conn.getResponseCode();
		BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		while((line=br.readLine())!=null){
		 buffer+=line;
		}
		br.close();

		//in a real app, the response would likely be some json, or info to use within the
		//app processing. But in this example, the response is just some text for us to display
		//back to the user to show the processing performed by the RS.
		out.println("Response from RS was <br><br>[START_RESPONSE_FROM_RS]<br>"+buffer+"<br>[END_RESPONSE_FROM_RS]");
	}

}
