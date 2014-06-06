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

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.EnvironmentType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.ResultType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.core.model.policy.AttributeAssignmentType;
import org.jboss.security.xacml.core.model.policy.ObligationType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.picketlink.identity.federation.api.soap.SOAPSAMLXACML;
import com.google.gson.Gson;

/**
 * UCONPEP Service that intercepts User Request to provide Authorization
 * Decision
 * 
 * @author Muhammad Sadiq Alvi
 * 
 */
@Path("/uconpep")
public class UCONPEP {
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public String helloPEP() {
		return "Hello PEP";
	}

	static int called = 0;
	static long lastTimeCalled = 0;
	static String jsonR = null;

	/**
	 * Takes in JSON Request for Authorization and returns JSON Response
	 * 
	 * @param jsonRequest
	 * @return
	 */
	@POST
	public String getAccessDecision(String jsonRequest) {

		ResponseContext response = null;
		/**
		 * @code{endpoint is the address pf PDP listening
		 */
		String endpoint = "http://localhost:8081/com.aislab.accesscontrol.jboss.pdp/SOAPServlet";
		RequestType reqType = new RequestType();
		String jsonResp = null;
		FileInputStream fis;
		RequestContext request = null;
		try {

			Gson gson = new Gson();

			/**
			 * creating Request with the json String
			 */
			JSONObject jsonObj;

			jsonObj = new JSONObject(jsonRequest);
			ResourceType resourceType = new ResourceType();
			if (jsonObj.has("id"))
				System.out.println("id " + jsonObj.getString("id"));
			if (jsonObj.has("adminId"))
				System.out.println("adminId " + jsonObj.getString("adminId"));
			SubjectType subjectType = new SubjectType();
			if (jsonObj.has("agreement"))
				resourceType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType(
								"agreement", null,
								jsonObj.getString("agreement")));
			if (jsonObj.has("ad"))
				resourceType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType("ad",
								null, jsonObj.getString("ad")));
			else
				subjectType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType("ad",
								null, "true"));
			if (jsonObj.has("id")) {
				subjectType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType(
								"user-id", null, jsonObj.getString("id")));
				System.out.println("It was Id : " + jsonObj.getString("id"));
			} else
				System.out.println("No Id Was There !!");
			if (jsonObj.has("session"))
				subjectType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType(
								"session", null, jsonObj.getString("session")));
			ActionType actionType = new ActionType();
			EnvironmentType evnType = new EnvironmentType();
			if (jsonObj.has("time")) {

				SimpleDateFormat parser = new SimpleDateFormat("HH:mm:ss");

				Date date = new Date();
				String time = parser.format(date);
				evnType.getAttribute().add(
						RequestAttributeFactory.createStringAttributeType(
								"time", null, time));

			}
			if (jsonObj.has("location")) {
				evnType.getAttribute()
						.add(RequestAttributeFactory.createStringAttributeType(
								"location", null, jsonObj.getString("location")));
			}
			reqType.getSubject().add(subjectType);
			reqType.getResource().add(resourceType);
			reqType.setAction(actionType);
			reqType.setEnvironment(evnType);
			List<ActionType> actType = new ArrayList();
			actType.add(actionType);
			List<EnvironmentType> environType = new ArrayList();
			environType.add(evnType);

			request = RequestResponseContextFactory.createRequestCtx();
			System.out.println("--------> Marshalling Request <---------");
			request.setRequest(reqType);
			request.marshall(System.out);

			SOAPSAMLXACML soapSAMLXACML = new SOAPSAMLXACML();
			/**
			 * Sending Request for Evaluation to PDP in SAML envelope and
			 * getting the response
			 */
			ResultType result = soapSAMLXACML.send(endpoint, "junaid", reqType);
			String timeValueForReEvaluation = null;
			String preUpdateAValue = null, preUpdateId = null;
			String postUpdateAValue = null, postUpdateId = null;
			ArrayList<String> preUpdateIdAndValue = new ArrayList<String>();
			ArrayList<String> postUpdateIdAndValue = new ArrayList<String>();
			ArrayList<String> onUpdateIdAndValue = new ArrayList<String>();
			String responseString = "";
			responseString = result.getDecision().toString();
			if (responseString.equals("NOT_APPLICABLE")) {
				responseString = "NotApplicable";
			}

			System.out.println("Response is : " + responseString);
			if (result != null && result.getObligations() != null) {
				System.out.println("Response From SAML is : "
						+ result.getObligations().getObligation().get(0)
								.getObligationId());
				Iterator<ObligationType> obIter = result.getObligations()
						.getObligation().iterator();
				/**
				 * Parsing Response returned for Obligations
				 */

				while (obIter.hasNext()) {
					ObligationType obType = (ObligationType) obIter.next();
					Iterator<AttributeAssignmentType> attIter = obType
							.getAttributeAssignment().iterator();
					System.out.println("Obl Id : is "
							+ obType.getObligationId());
					if (obType.getAttributeAssignment().isEmpty())
						System.out.println("No Attribute Assignments");

					while (attIter.hasNext()) {
						AttributeAssignmentType aaType = attIter.next();
						String aaId = aaType.getAttributeId();
						System.out.println(aaId);
						String aaVal = aaType.getContent().get(0).toString();

						String[] spllittedVal = aaVal.split(" ");
						if (obType.getObligationId()
								.equals("urn:xacml:ucon:on")
								&& aaId.equals("request_interval")) {

							System.out.println("Req Val : " + aaVal);
							System.out.println("Splitted Val : "
									+ spllittedVal[1]);
							String intervalReq = "";
							for (int i = 0; i < spllittedVal[1].length(); i++) {
								if (spllittedVal[1].charAt(i) != '\"') {
									intervalReq += spllittedVal[1].charAt(i);
								}
							}
							System.out.println("Interval is : " + intervalReq);
							timeValueForReEvaluation = intervalReq;
						}

						if (obType.getObligationId().equals(
								"urn:xacml:ucon:preUpdate")
								&& aaId.contains("update_")) {

							System.out.println("Splitted Val : "
									+ spllittedVal[1]);
							String preVal = "";
							for (int i = 0; i < spllittedVal[1].length(); i++) {
								if (spllittedVal[1].charAt(i) != '\"') {
									preVal += spllittedVal[1].charAt(i);
								}
							}
							System.out.println("PreVal is : " + preVal);
							preUpdateId = aaId;
							System.out.println("Splitted Val : "
									+ spllittedVal[1]);
							String preUVal = "";
							for (int i = 0; i < spllittedVal[1].length(); i++) {
								if (spllittedVal[1].charAt(i) != '\"') {
									preUVal += spllittedVal[1].charAt(i);
								}
							}
							System.out.println("Interval is : " + preUVal);
							preUpdateAValue = preUVal;
							preUpdateIdAndValue.add(preUpdateId + " "
									+ preUpdateAValue);
							System.out.println("Pre Val : " + aaVal);
						}
						if (obType.getObligationId().equals(
								"urn:xacml:ucon:onGoingUpdate")
								&& aaId.contains("update_")) {
							System.out.println("Splitted Val : "
									+ spllittedVal[1]);
							String onUVal = "";
							for (int i = 0; i < spllittedVal[1].length(); i++) {
								if (spllittedVal[1].charAt(i) != '\"') {
									onUVal += spllittedVal[1].charAt(i);
								}
							}
							System.out.println("OnUpdate is : " + onUVal);

							onUpdateIdAndValue.add(aaId + " " + onUVal);
							System.out.println("On Val : " + aaVal);
						}
						if (obType.getObligationId().equals(
								"urn:xacml:ucon:postUpdate")
								&& aaId.contains("update_")) {
							postUpdateId = aaId;
							System.out.println("Splitted Val : "
									+ spllittedVal[1]);
							String postUVal = "";
							for (int i = 0; i < spllittedVal[1].length(); i++) {
								if (spllittedVal[1].charAt(i) != '\"') {
									postUVal += spllittedVal[1].charAt(i);
								}
							}
							System.out.println("PostUpdate is : " + postUVal);
							postUpdateAValue = postUVal;
							postUpdateIdAndValue.add(postUpdateId + " "
									+ postUpdateAValue);
							System.out.println("post Val : " + aaVal);
						}
					}

				}
			}
			System.out.println("Called : " + called++);

			/**
			 * Creating json response to be returned
			 */

			if (timeValueForReEvaluation != null
					&& timeValueForReEvaluation.length() > 0) {
				responseString += " " + "interval" + " "
						+ timeValueForReEvaluation;

				System.out.println("Time is : " + timeValueForReEvaluation);
			}
			if (preUpdateIdAndValue.size() > 0) {
				Iterator<String> preUpdateIter = preUpdateIdAndValue.iterator();
				while (preUpdateIter.hasNext()) {
					responseString += " " + "pre" + preUpdateIter.next();
					System.out.println(responseString);
				}

			}
			if (onUpdateIdAndValue.size() > 0) {
				Iterator<String> onUpdateIter = onUpdateIdAndValue.iterator();
				while (onUpdateIter.hasNext()) {
					responseString += " " + "on" + onUpdateIter.next();
					System.out.println(responseString);
				}
			}
			if (postUpdateIdAndValue.size() > 0) {
				Iterator<String> postUpdateIter = postUpdateIdAndValue
						.iterator();
				while (postUpdateIter.hasNext()) {
					responseString += " " + "post" + postUpdateIter.next();
					System.out.println(responseString);
				}
			}
			jsonResp = gson.toJson(responseString);

		} catch (Exception e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} finally {
			try {
				if (request != null)
					request.marshall(System.out);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		System.out.println(jsonResp);
		jsonR = jsonResp;
		return jsonResp;

	}

	/**
	 * Returns User Id
	 * @param uid
	 * @return
	 */
	@POST
	@Path("/postUser")
	public String postUser(String uid) {
		try {
			JSONObject jsonObj = new JSONObject(uid);

			System.out.println("id " + jsonObj.getString("id"));
			System.out.println("adminId " + jsonObj.getString("adminId"));
		}

		catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(uid);
		return uid;
	}

}
