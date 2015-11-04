package net.wasdev.securemicroservices;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.Hashtable;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;

import java.security.*;
import java.security.cert.*;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.security.auth.Subject;

import com.ibm.websphere.security.auth.WSSubject;
import com.ibm.websphere.security.WSSecurityException;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.*;
import io.jsonwebtoken.impl.crypto.*;

@WebServlet("/Test")
public class TestServlet extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		PrintWriter out = response.getWriter();
		out.println("<html><body><h2>RP Signed JWT App</h2><br>");

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

		String id_token = theChosenOne.get("id_token").toString();

		out.println("ID Token was : "+id_token+"<br>");
		out.println("Building new JWT to call RS with <br>");

    //get the keystores specified in the server.xml
    String locationOfSigningKeyStore = null;
		String locationOfTrustKeyStore = null;
		//password and certificate alias for the keystore we'll use to sign the jwts
		String signingKeystorePw = null;
		String signingCertAlias = null;
		//password and certificate alias for the keystore we'll use to verify id_token
		String trustKeystorePw = null;
		String trustCertAlias = null;
		try{
			//this is the keystore we'll use to sign our jwt that we pass to the RS
			locationOfSigningKeyStore = new InitialContext().lookup("signingKeyStore").toString();
			signingKeystorePw = new InitialContext().lookup("signingKeyStorePw").toString();
			signingCertAlias = new InitialContext().lookup("signingKeyStoreAlias").toString();
			//this is the location of the keystore we need to verify the trust of the id_token from the OP.
			locationOfTrustKeyStore = new InitialContext().lookup("trustKeyStore").toString();
			trustKeystorePw = new InitialContext().lookup("trustKeyStorePw").toString();
			trustCertAlias = new InitialContext().lookup("trustKeyStoreALias").toString();
			out.println("Signing JWTs using keystore From location : "+locationOfSigningKeyStore);
			out.println("Trusting JWTs using keystore From location : "+locationOfTrustKeyStore);
		}catch(NamingException e){
			throw new IOException(e);
		}



    try{
			//load up the keystores..
			FileInputStream is = new FileInputStream(locationOfSigningKeyStore);
			KeyStore signingKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
			signingKeystore.load(is,signingKeystorePw.toCharArray());
			is = new FileInputStream(locationOfTrustKeyStore);
			KeyStore trustKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustKeystore.load(is,trustKeystorePw.toCharArray());

			//grab the keys we'll use to sign & verify trust.
			PublicKey trustkey = trustKeystore.getCertificate(trustCertAlias).getPublicKey();
			Key signingkey = signingKeystore.getKey(signingCertAlias,signingKeystorePw.toCharArray());

			//parse the id token into a jws with claims,
			//the parser it will throw an exception if the signing is not valid according to
			//the signing key passed in.
      Jws<Claims> jwt = Jwts.parser().setSigningKey(trustkey).parseClaimsJws(id_token);
			Claims claims = jwt.getBody();

			out.println("ID_TOKEN Subject : "+claims.get("sub")+"<br>");

			//Now we'll build our jwt that we'll pass to the RS.
			//we sign this one ourselves, and the RS can verify it with our public key.
      Claims onwardsClaims = Jwts.claims();
			//add in the subject & scopes from the original id_token
      onwardsClaims.setSubject(claims.getSubject());
      onwardsClaims.put("scope",theChosenOne.get("scope").toString());
			//set a very short lifespan for the new jwt of 30 seconds.
      Calendar calendar = Calendar.getInstance();
      calendar.add(Calendar.SECOND,30);
      onwardsClaims.setExpiration(calendar.getTime());
			//finally build the new jwt, using the claims we just built, signing it with our
			//signing key, and adding the key alias as kid to the encryption header, which is
			//optional, but can be used as hint by the receivers of the jwt to know which key
			//they should verifiy it with.
      String newJwt = Jwts.builder().setHeaderParam("kid",signingCertAlias).setClaims(onwardsClaims).signWith(SignatureAlgorithm.RS256,signingkey).compact();

			//print the new jwt out to the browser so we can follow along with the progress =)
			out.println("Have built new JWT "+newJwt);

			//call the RS with the jwt we just built.
			String line,buffer="";
			URL introspectourl = new URL("https://127.0.0.1:9602/signed-jwt-rs-application/Test");
			HttpURLConnection conn = (HttpURLConnection)introspectourl.openConnection();
			conn.setRequestMethod("POST");

			//invoke the request, sending the access_token as the post paramter 'token'
			conn.setDoOutput(true);
			OutputStreamWriter wrToken = new OutputStreamWriter(conn.getOutputStream());
			wrToken.write("jwt=" + newJwt);
			wrToken.flush();
			wrToken.close();

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

		}catch(io.jsonwebtoken.SignatureException e){
			//thrown if the signature on id_token cannot be verified.
			throw new IOException(e);
		}catch(KeyStoreException e){
			throw new IOException(e);
		}catch(NoSuchAlgorithmException e){
			throw new IOException(e);
		}catch(CertificateException e){
			throw new IOException(e);
		}catch(UnrecoverableKeyException e){
			throw new IOException(e);
		}
	}

}
