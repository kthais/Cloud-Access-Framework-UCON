/******************************************************************************
 * Project:    Extensible Access Control Framework for Cloud based Applications.
 *                     http://ais.seecs.nust.edu.pk/project/ 
 * Developed by: KTH- Applied Information Security Lab (AIS), 
 *                       NUST-SEECS, H-12 Campus, 
 *                       Islamabad, Pakistan. 
 *                       www.ais.seecs.nust.edu.pk
 * Funded by: National ICT R&D Fund, Ministry of Information Technology & Telecom,
 *                  http://www.ictrdf.org.pk/
 * Copyright (c) 2013-2015 All Rights Reserved, AIS-SEECS NUST & National ICT R&D Fund

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy and/or modify the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

package com.aislab.accesscontrol.jboss.ucon.pep;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.EnvironmentType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.cedarsoftware.util.io.JsonReader;
import com.google.gson.Gson;

/**
 * This is the Context Handler class which converts JSON Request from Moodle to
 * XACML
 * 
 * @author Muhammad Sadiq Alvi
 * 
 */
@SuppressWarnings("deprecation")
@Path("/contexthandler")
public class ContextHandlerService {

	/**
	 * Transforms JSON Request to XACML
	 * 
	 * @param jsonRequest
	 * @return String XACML
	 */
	@POST
	public String transformRequesttoXACML(String jsonRequest) {
		String jsonResponse = null;
		PEPResponse responded = null;
		PEPResponse reCon = null;
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(
				"http://localhost:8080/com.aislab.accesscontrol.jboss.ucon.pep/rest/uconpep/getaccessdecision");
		JSONObject jsonObj;
		try {
			jsonObj = new JSONObject(jsonRequest);
			System.out.println("id " + jsonObj.getString("id"));
			System.out.println("adminId " + jsonObj.getString("adminId"));
			SubjectType subjectType = new SubjectType();
			subjectType.getAttribute().add(
					RequestAttributeFactory.createStringAttributeType(
							"user-id", null, jsonObj.getString("id")));
			// subjectType.getAttribute().add(RequestAttributeFactory.createStringAttributeType("group","admin@users.example.com","developers"));
			// subjectType.getAttribute().add(RequestAttributeFactory.createStringAttributeType("Account","admin","100"));
			RequestType reqType = new RequestType();
			ResourceType resourceType = new ResourceType();
			resourceType.getAttribute().add(
					RequestAttributeFactory.createStringAttributeType("mysql",
							null, "urn:oasis:org:resources:mysql"));
			ActionType actionType = new ActionType();
			actionType.getAttribute().add(
					RequestAttributeFactory.createStringAttributeType(
							"urn:oasis:names:tc:xacml:1.0:action:action-id",
							null, "access"));

			EnvironmentType evnType = new EnvironmentType();
			if (jsonObj.getString("time") != null) {
				evnType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType(
								"time", null, jsonObj.getString("time")));
			}
			reqType.getSubject().add(subjectType);
			reqType.getResource().add(resourceType);
			reqType.setAction(actionType);
			reqType.setEnvironment(evnType);
			Gson gson = new Gson();
			// jsonRequest.put("request", req);
			// JSONEntity jsonEntity;
			String jsonReqString = gson.toJson(reqType);

			// JsonWriter.objectToJson(req);
			StringEntity stringRequest = new StringEntity(jsonReqString);
			post.setEntity(stringRequest);// new
											// UrlEncodedFormEntity(nameValuePairs));
			// gson.fromJson(jsonRequest.toString(), RequestContext.class);
			HttpResponse response = client.execute(post);
			byte[] tempArr = new byte[1000];
			for (int i = 0; i < tempArr.length; i++) {
				tempArr[i] = 0;
			}
			response.getEntity().getContent().read(tempArr);
			jsonResponse = "";
			for (int i = 0; i < tempArr.length; i++) {
				if (tempArr[i] != 0)
					jsonResponse += (char) tempArr[i];
			}
			System.out.println("From Context handler " + jsonResponse);

		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {

			try {
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return jsonResponse;
		}

	}

}
