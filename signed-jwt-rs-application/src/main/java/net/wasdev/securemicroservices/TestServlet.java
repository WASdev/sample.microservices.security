package net.wasdev.securemicroservices;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.FileInputStream;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import java.security.*;
import java.security.cert.*;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		PrintWriter out = response.getWriter();

		String jwtParam = request.getParameter("jwt");

		out.println("RS App got jwt "+jwtParam+"<br>");

		//get the keystore info specified in the server.xml
		String locationOfTrustKeyStore = null;
		String trustKeystorePw = null;
		String trustCertAlias = null;
		try{
			//this is the location of the keystore we need to verify the trust of the jwt from the RP
			locationOfTrustKeyStore = new InitialContext().lookup("trustKeyStore").toString();
			out.println("Trusting JWTs using keystore From location : "+locationOfTrustKeyStore+"<br><br>");
			//now grab the password & alias to use with the keystore
			trustKeystorePw = new InitialContext().lookup("trustKeyStorePw").toString();
			trustCertAlias = new InitialContext().lookup("trustKeyStoreAlias").toString();
		}catch(NamingException e){
			throw new IOException(e);
		}

	  try{
			//load up the keystore..
			FileInputStream is = new FileInputStream(locationOfTrustKeyStore);
			KeyStore trustKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustKeystore.load(is,trustKeystorePw.toCharArray());

			//grab the key we'll use verify trust.
			PublicKey trustkey = trustKeystore.getCertificate(trustCertAlias).getPublicKey();

			//parse the id token into a jws with claims,
			//the parser it will throw an exception if the signing is not valid according to
			//the signing key passed in.
			Jws<Claims> jwt = Jwts.parser().setSigningKey(trustkey).parseClaimsJws(jwtParam);
			Claims claims = jwt.getBody();

			out.println("JWT Validated ok<br>");
			out.println("Scopes: "+claims.get("scope")+"<br>");

			//here we could now filter our processing on if a given scope is present
			//in the scope set.


		}catch(io.jsonwebtoken.SignatureException e){
			//thrown if the signature on id_token cannot be verified.
			out.println("JWT did NOT validate ok");
		}catch(ExpiredJwtException e){
			//thrown if the jwt had expired. Eg current time is past the expiration time in the jwt
			//this example has jwts with a 30 second lifespan.
			out.println("JWT had expired!");
		}catch(KeyStoreException e){
			throw new IOException(e);
		}catch(NoSuchAlgorithmException e){
			throw new IOException(e);
		}catch(CertificateException e){
			throw new IOException(e);
		}
	}
}
