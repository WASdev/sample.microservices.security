package net.wasdev.securemicroservices;

//Copyright 2015 IBM Corp.

import javax.annotation.PostConstruct;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.wasdev.securemicroservices.common.APIKey;

@Path("/Greeting")
public class GreetingService {
	//the ID for this service
	private static final String SERVICE_ID = "1";	
	//the name of the system property that contains the shared key
	private static final String SYSPROP_SECRET = "APIKEY";
	//full URL of the service to be called
	private static final String ENV_REMOTE_SVC = "naming.service";

	private String svcurl = null;	//the URL for the service to call 		
	
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public String getMessage() {
		Client client = ClientBuilder.newClient();
		//register the API key generator for use with the client call
		APIKey apikey = new APIKey(SERVICE_ID, SYSPROP_SECRET);
		client.register(apikey);
		
		//make the request
		String log = "Target set in JAXRS client : " + svcurl + "?id=1&full=true\n";
		WebTarget target = client.target(svcurl + "?id=1&full=true");
		Invocation.Builder builder = target.request(MediaType.APPLICATION_JSON);
		Response response =  builder.build("GET").invoke();
		String resp = response.readEntity(String.class);
		response.close();
		
		//write out the response
		log += System.getProperty(APIKey.SYSPROP_LOGGING);
		log += "\nText returned from service : \n" + resp;
		return log;
	}
	
	@PostConstruct
	public void init() {
		svcurl = System.getProperty(ENV_REMOTE_SVC, System.getenv(ENV_REMOTE_SVC));
	}
}
