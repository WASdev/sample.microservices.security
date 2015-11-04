package net.wasdev.securemicroservices;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.PrintWriter;

import java.io.OutputStreamWriter;
import java.io.InputStream;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import java.net.HttpURLConnection;
import java.net.URL;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

@WebServlet("/Test")
public class TestServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, UnsupportedEncodingException {
		//obtain the access_token from the request.
		//in this case, we're passing it as a request parameter.
		String access_token = request.getParameter("token");

		//get our client info from the server.xml
		String clientid = null;
		String clientsecret = null;
		String introspectUrl = null;
		try{
			clientid = new InitialContext().lookup("oidcClientId").toString();
			clientsecret = new InitialContext().lookup("oidcClientPw").toString();
			introspectUrl = new InitialContext().lookup("introspectUrl").toString();
		}catch(NamingException e){
			throw new IOException(e);
		}

		//call the OP with the access_token to introspect the id info.
		String line,buffer="";
		URL introspectourl = new URL(introspectUrl);
		HttpURLConnection conn = (HttpURLConnection)introspectourl.openConnection();
		conn.setRequestMethod("POST");

		//Basic auth, using clientid & secret for microservice1 in OP
		String auth = clientid+":"+clientsecret;
		String basic = "Basic "+DatatypeConverter.printBase64Binary(auth.getBytes());

		//add the Auth header.
		conn.setRequestProperty("Authorization",basic);

		//invoke the request, sending the access_token as the post paramter 'token'
		conn.setDoOutput(true);
		OutputStreamWriter wrToken = new OutputStreamWriter(conn.getOutputStream());
		wrToken.write("token=" + access_token);
		wrToken.flush();
		wrToken.close();

		//take the result back as a json object.
		InputStream is = conn.getInputStream();
		JsonReader jsonReader = Json.createReader(is);
		JsonObject obj = jsonReader.readObject();
		jsonReader.close();
		is.close();

		//query the result to test if the token is still active.
		//it may have expired if the request has been sent using a cached
		//token, or if the request is a replay attack.
		//the OP tells us if the access_token  is still active in the response.
		Boolean isActive = obj.getBoolean("active");

		//build our response back to the caller.
		PrintWriter out = response.getWriter();
		if(isActive){
			out.println("Token is still active.<br>");
			out.println("Scope : "+obj.getString("scope")+"<br>");

			//here we could now filter our processing on if a given scope is present
			//in the scope set.

			//instead we'll just dump the full token, so you can see all the other info
			//that came back from the introspection.
			out.println("Full Introspection Response : "+obj.toString());

		}else{
			out.println("Token has expired. RS will not do further processing");
		}

	}

}
