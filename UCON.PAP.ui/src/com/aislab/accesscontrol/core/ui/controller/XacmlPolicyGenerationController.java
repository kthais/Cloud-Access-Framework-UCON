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

package com.aislab.accesscontrol.core.ui.controller;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.ui.dao.PolicyDAO;
import com.aislab.accesscontrol.core.ui.util.XACMLPolicyGenerationUtil;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code XacmlPolicySetGeneration}
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class XacmlPolicyGenerationController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(XacmlPolicyGenerationController.class
			.getName());
	/**
	 * An instance of {@code PolicyDAO} for using methods to access data related
	 * to {@code Policy}
	 */
	PolicyDAO daoPolicy = new PolicyDAO();
	/**
	 * An instance of {@code XACMLPolicyGenerationUtil} for using utility
	 * methods to generate an XACML Policy.
	 */
	XACMLPolicyGenerationUtil polUtil = new XACMLPolicyGenerationUtil();
	/**
	 * An instance of {@code Policy} used to store the {@code Policy} selected
	 * by the user from the user interface.
	 */
	Policy selectedPolicy;
	/**
	 * An ArrayList of {@code Policy} used to display all the existing
	 * {@code Policy} instances stored in the database.
	 */
	ArrayList<Policy> policyList = new ArrayList<Policy>();
	/**
	 * A {@code boolean} variable to check whether the XACML Policy Set was
	 * successfully generated or not.
	 */
	boolean successfulGeneration;

	/**
	 * A string variable used to store fileContent of a policy
	 */
	public String fileContent;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the {@code policyList} property to {@code ArrayList} argument.
	 * 
	 * @param allPolicy
	 */
	public void setPolicyList(ArrayList<Policy> allPolicy) {
		this.policyList = allPolicy;
		log.debug("Set  policyList: " + policyList);

	}

	/**
	 * Sets the {@code polUtil} property to {@code XACMLPolicyGenerationUtil}
	 * argument.
	 * 
	 * @param polUtil
	 */
	public void setPolUtil(XACMLPolicyGenerationUtil polUtil) {
		this.polUtil = polUtil;
	}

	/**
	 * Sets the {@code successfulGeneration} property to {@code boolean}
	 * argument.
	 * 
	 * @param successfulGeneration
	 */
	public void setSuccessfulGeneration(boolean successfulGeneration) {
		this.successfulGeneration = successfulGeneration;
	}

	/**
	 * Sets the {@code selectedPolicy} property to {@code Policy} argument.
	 * 
	 * @param selectedPolicy
	 */
	public void setSelectedPolicy(Policy selectedPolicy) {
		this.selectedPolicy = selectedPolicy;
		log.debug("Set  selectedPolicy: " + selectedPolicy);
	}

	/**
	 * Sets the {@code daoPolicy} property to {@code PolicyDAO} argument.
	 * 
	 * @param daoPolicy
	 */
	public void setDaoPolicy(PolicyDAO daoPolicy) {
		this.daoPolicy = daoPolicy;
		log.debug("Set  daoPolicy: " + daoPolicy);
	}

	/**
	 * Sets the {@code fileContent} property to {@code String} argument.
	 * 
	 * @param fileContent
	 */
	public void setFileContent(String fileContent) {
		this.fileContent = fileContent;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns the value of {@code daoPolicy} property.
	 * 
	 * @return daoPolicy
	 */
	public PolicyDAO getDaoPolicy() {
		log.debug("Get  daoPolicy: " + daoPolicy);
		return daoPolicy;
	}

	/**
	 * Returns the value of {@code selectedPolicy} property.
	 * 
	 * @return selectedPolicy
	 */
	public Policy getSelectedPolicy() {
		log.debug("Get  selectedPolicy: " + selectedPolicy);
		return selectedPolicy;
	}

	/**
	 * Returns the value of {@code polUtil} property.
	 * 
	 * @return polUtil
	 */
	public XACMLPolicyGenerationUtil getPolUtil() {
		return polUtil;
	}

	/**
	 * Returns the value of {@code policyList} property.
	 * 
	 * @return policyList
	 */
	public ArrayList<Policy> getPolicyList() {
		log.debug("Getting policyList ");
		return (ArrayList<Policy>) daoPolicy.selectPolicy();
	}

	/**
	 * Returns the value of {@code successfulGeneration} property.
	 * 
	 * @return successfulGeneration
	 */
	public boolean isSuccessfulGeneration() {
		return successfulGeneration;
	}

	/**
	 * Returns the value of {@code fileContent} property.
	 * 
	 * @return fileContent
	 */
	public String getFileContent() {
		return fileContent;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Generates an XACML Policy.
	 * 
	 * @throws IOException
	 */
	public void generateXACMLPolicy() throws IOException {
		FacesContext context = FacesContext.getCurrentInstance();

		if (this.selectedPolicy != null) {
			successfulGeneration = polUtil
					.generateXACMLPolicy(this.selectedPolicy.getPkPolicy());

			if (successfulGeneration) {
				log.info(this.selectedPolicy.getPolicyId()
						+ " successfully generated!");
				context.addMessage(null,
						new FacesMessage(this.selectedPolicy.getPolicyId()
								+ " successfully generated!", ""));
			} else {
				log.info("Error occured while generating "
						+ this.selectedPolicy.getPolicyId());
				context.addMessage(null,
						new FacesMessage("Error occured while generating "
								+ this.selectedPolicy.getPolicyId(), ""));
			}
		} else {
			log.info("No Policy Selected. Please select a policy to generate XACML.");

			RequestContext.getCurrentInstance().showMessageInDialog(
					new FacesMessage("No Policy Selected ",
							"Please select a policy to generate XACML."));
		}
	}

	/**
	 * Generates all XACML Policies.
	 * 
	 * @throws IOException
	 */
	public void generateAllXACMLPolicies() throws IOException {
		log.info("Generating All XACML Policies.");
		FacesContext context = FacesContext.getCurrentInstance();

		successfulGeneration = polUtil
				.generateAllXACMLPolicies(getPolicyList());

		if (successfulGeneration) {
			log.info("All Policies successfully generated!");
			context.addMessage(null, new FacesMessage(
					"All Policies successfully generated!", ""));
		} else {
			log.info("Error occured while generating all policies!");
			context.addMessage(null, new FacesMessage(
					"Error occured while generating all policies!", ""));
		}

	}

	/**
	 * View an XACML Policy.
	 * 
	 * @throws IOException
	 */

	public void viewXACMLPolicy() throws IOException {

		if (this.selectedPolicy != null) {

			String filename = this.selectedPolicy.getPolicyId() + "_P.xml";
			String[] parseString = filename.split(" ");
			String semiFinalFileName = "";
			for(int i = 0; i < parseString.length; i++){
				semiFinalFileName += parseString[i];
			}
			String finalFileName = "";
			String[] secondParse = semiFinalFileName.split(":");
			for(int i = 0; i < secondParse.length; i++)
				finalFileName += secondParse[i];
			File file = new File("C:\\", finalFileName);
			if (file.exists()) {

				Desktop dt = Desktop.getDesktop();
				try {
					dt.open(file);
				} catch (IOException e) {
					e.printStackTrace();
				}

			} else {
				log.info("No Policy genertaed. Please generate the policy first to view XACML.");

				RequestContext
						.getCurrentInstance()
						.showMessageInDialog(
								new FacesMessage("No Policy Exists ",
										"Please generate the policy first to view XACML."));

			}

		} else {
			log.info("No Policy Selected. Please select a policy to view XACML.");

			RequestContext.getCurrentInstance().showMessageInDialog(
					new FacesMessage("No Policy Selected ",
							"Please select the policy first to view XACML."));

		}
	}

}
