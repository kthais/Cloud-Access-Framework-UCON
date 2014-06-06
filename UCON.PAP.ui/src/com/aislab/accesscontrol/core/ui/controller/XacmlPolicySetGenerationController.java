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

import com.aislab.accesscontrol.core.entities.PolicySet;
import com.aislab.accesscontrol.core.ui.dao.PolicySetDAO;
import com.aislab.accesscontrol.core.ui.util.XACMLPolicySetGenerationUtil;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code XacmlPolicySetGeneration}
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class XacmlPolicySetGenerationController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger
			.getLogger(XacmlPolicySetGenerationController.class.getName());
	/**
	 * An instance of {@code PolicySetDAO} for using methods to access data
	 * related to {@code PolicySet}
	 */
	PolicySetDAO daoPolicySet = new PolicySetDAO();
	/**
	 * An instance of {@code XACMLPolicySetGenerationUtil} for using utility
	 * methods to generate an XACML Policy Set.
	 */
	XACMLPolicySetGenerationUtil polUtil = new XACMLPolicySetGenerationUtil();
	/**
	 * An instance of {@code PolicySet} used to store the {@code PolicySet}
	 * selected by the user from the user interface.
	 */
	PolicySet selectedPolicySet;
	/**
	 * An ArrayList of {@code PolicySet} used to display all the existing
	 * {@code PolicySet}s stored in the database.
	 */
	ArrayList<PolicySet> policySetList = new ArrayList<PolicySet>();
	/**
	 * A {@code boolean} variable to check whether the XACML Policy Set was
	 * successfully generated or not.
	 */
	boolean successfulGeneration;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the value of {@code selectedPolicySet} property to {@code PolicySet}
	 * argument.
	 * 
	 * @param selectedPolicySet
	 */
	public void setSelectedPolicySet(PolicySet selectedPolicySet) {
		this.selectedPolicySet = selectedPolicySet;
		log.debug("Set  selectedPolicySet: " + selectedPolicySet);

	}

	/**
	 * Sets the value of {@code daoPolicySet} property to {@code PolicySetDAO}
	 * argument.
	 * 
	 * @param daoPolicySet
	 */
	public void setDaoPolicySet(PolicySetDAO daoPolicySet) {
		this.daoPolicySet = daoPolicySet;
		log.debug("Set  daoPolicySet: " + daoPolicySet);
	}

	/**
	 * Sets the value of {@code polUtil} property to
	 * {@code XACMLPolicySetGenerationUtil} argument.
	 * 
	 * @param polUtil
	 */
	public void setPolUtil(XACMLPolicySetGenerationUtil polUtil) {
		this.polUtil = polUtil;
	}

	/**
	 * Sets the value of {@code successfulGeneration} property to
	 * {@code boolean} argument.
	 * 
	 * @param successfulGeneration
	 */
	public void setSuccessfulGeneration(boolean successfulGeneration) {
		this.successfulGeneration = successfulGeneration;
	}

	/**
	 * Sets the value of {@code policySetList} property to {@code ArrayList}
	 * argument.
	 * 
	 * @param policySetList
	 */
	public void setPolicySetList(ArrayList<PolicySet> policySetList) {
		this.policySetList = policySetList;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Returns the value of {@code selectedPolicySet} property.
	 * 
	 * @return selectedPolicySet
	 */
	public PolicySet getSelectedPolicySet() {
		log.debug("Get  selectedPolicySet: " + selectedPolicySet);
		return selectedPolicySet;
	}

	/**
	 * Returns the value of {@code daoPolicySet} property.
	 * 
	 * @return daoPolicySet
	 */
	public PolicySetDAO getDaoPolicySet() {
		log.debug("Get  daoPolicySet: " + daoPolicySet);
		return daoPolicySet;
	}

	/**
	 * Returns the value of {@code policySetList} property.
	 * 
	 * @return policySetList
	 */
	public ArrayList<PolicySet> getPolicySetList() {
		log.debug("Getting  policySetList");
		return (ArrayList<PolicySet>) daoPolicySet.selectPolicySet();
	}

	/**
	 * Returns the value of {@code polUtil} property.
	 * 
	 * @return polUtil
	 */
	public XACMLPolicySetGenerationUtil getPolUtil() {
		return polUtil;
	}

	/**
	 * Returns the value of {@code successfulGeneration} property.
	 * 
	 * @return successfulGeneration
	 */
	public boolean isSuccessfulGeneration() {
		return successfulGeneration;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Generates an XACML Policy Set.
	 * 
	 * @throws IOException
	 */
	public void generateXACMLPolicySet() throws IOException {

		if (this.selectedPolicySet != null) {
			successfulGeneration = polUtil
					.generateXACMLPolicySet(this.selectedPolicySet
							.getPkPolicySet());
			FacesContext context = FacesContext.getCurrentInstance();
			if (successfulGeneration) {
				log.info(this.selectedPolicySet.getPolicySetId()
						+ " successfully generated!");
				context.addMessage(null, new FacesMessage(
						this.selectedPolicySet.getPolicySetId()
								+ " successfully generated!", ""));
			} else {
				log.info("Error occured while generating "
						+ this.selectedPolicySet.getPolicySetId());
				context.addMessage(null, new FacesMessage(
						"Error occured while generating "
								+ this.selectedPolicySet.getPolicySetId(), ""));
			}
		}

		else {
			log.info("No Policy Set Selected. Please select a policy set to generate XACML.");

			RequestContext.getCurrentInstance().showMessageInDialog(
					new FacesMessage("No Policy Set Selected",
							"Please select a policy set to generate XACML."));
		}
	}

	/**
	 * Generates all XACML Policy Set.
	 * 
	 * @throws IOException
	 */
	public void generateAllXACMLPolicySets() throws IOException {
		log.info("Generating All XACML Policy Sets.");

		FacesContext context = FacesContext.getCurrentInstance();

		successfulGeneration = polUtil
				.generateAllXACMLPolicySets(getPolicySetList());

		if (successfulGeneration) {
			log.info("All Policy Sets successfully generated!");
			context.addMessage(null, new FacesMessage(
					"All Policy Sets successfully generated!", ""));
		} else {
			log.info("Error occured while generating all policy sets!");
			context.addMessage(null, new FacesMessage(
					"Error occured while generating all policy sets!", ""));
		}

	}

	/**
	 * View an XACML PolicySet.
	 * 
	 * @throws IOException
	 */

	public void viewXACMLPolicySet() throws IOException {

		if (this.selectedPolicySet != null) {

			String filename = this.selectedPolicySet.getPolicySetId()
					+ "_PS.xml";
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
				log.info("No Policy Set genertaed. Please generate the Policy Set first to view XACML.");

				RequestContext
						.getCurrentInstance()
						.showMessageInDialog(
								new FacesMessage("No Policy Set Exists ",
										"Please generate the Policy Set first to view XACML."));

			}

		} else {
			log.info("No Policy Set Selected. Please select a policy set to view XACML.");

			RequestContext
					.getCurrentInstance()
					.showMessageInDialog(
							new FacesMessage("No Policy Set Selected ",
									"Please select the Policy Set first to view XACML."));

		}
	}

}
