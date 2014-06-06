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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.PolicySet;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.PolicyDAO;
import com.aislab.accesscontrol.core.ui.dao.PolicySetDAO;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code PolicySet} instance.
 * 
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */

@ManagedBean
@SessionScoped
public class AddPolicySetController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger
			.getLogger(AddPolicySetController.class.getName());

	/**
	 * An instance of {@code PolicySetDAO} for using methods to access data
	 * related to {@code PolicySet}
	 */
	PolicySetDAO daoPolicySet = new PolicySetDAO();

	/**
	 * An instance of {@code TargetDAO} for using methods to access data related
	 * to {@code Target}
	 */
	TargetDAO daoTarget = new TargetDAO();
	/**
	 * An instance of {@code PolicyDAO} for using methods to access data related
	 * to {@code Policy}
	 */
	PolicyDAO daoPolicy = new PolicyDAO();
	/**
	 * A {@code String} variable to store the value of {@code policySetId}
	 * attribute of the {@code PolicySet} instance to be created.
	 */
	private String policySetId = null;
	/**
	 * A {@code String} variable to store the value of {@code description}
	 * attribute of the {@code PolicySet} instance to be created.
	 */
	private String policySetDescription = null;
	/**
	 * A {@code List} variable to provide all the available policy combining
	 * algorithms.
	 */
	private List<String> policyCombiningAlgorithms = Arrays.asList(
			"First applicable", "Deny overrides", "Only one applicable",
			"Permit overrides", "Ordered permit overrides");

	/**
	 * A {@code Target} variable to store the {@code target} attribute of the
	 * {@code PolicySet} to be created.
	 */
	private Target selectedTarget;
	/**
	 * An {@code ArrayList} variable to provide all the available {@code Target}
	 * instance stored in the database.
	 */
	private ArrayList<Target> targetList = new ArrayList<Target>();

	/**
	 * An {@code ArrayList} variable to provide all the available
	 * {@code PolicySet} instance stored in the database which can be included
	 * in the {@code subPolicySets} attribute of the {@code PolicySet} instance
	 * to be created.
	 */
	private ArrayList<PolicySet> policySetList = new ArrayList<PolicySet>();
	/**
	 * A {@code List} variable to store the value of {@code } attribute of the
	 * {@code PolicySet} instance to be created.
	 */
	private List<PolicySet> selectedPolicySets;

	/**
	 * A {@code boolean} variable to check the applicability of policy set.
	 */
	private boolean applicableForAll = false;

	/**
	 * A {@code String } used to store all the policy sets selected by the user
	 * from the user interface in terms of policy set id.
	 */
	private ArrayList<String> selectedPolicySetIds = new ArrayList<String>();

	/**
	 * A {@code String } used to store the policy set selected by the user from
	 * the user interface in terms of policy set id.
	 */
	private String selectedPolicySetId;

	/**
	 * A {@code Lsit } used to store all the policies selected by the user from
	 * the user interface in terms of policy id.
	 */
	private ArrayList<String> selectedPolicyIds = new ArrayList<String>();

	/**
	 * A {@code String } used to store the policy set selected by the user from
	 * the user interface in terms of policy set id.
	 */
	private String selectedPolicyId;

	/**
	 * An {@code ArrayList} variable to provide all the available {@code Policy}
	 * instances stored in the database.
	 */
	private ArrayList<Policy> policyList = new ArrayList<Policy>();
	/**
	 * A {@code List} variable to store the {@code policies} attribute of
	 * {@code PolicySet} instance to be created.
	 */
	private List<Policy> selectedPolicies;

	/**
	 * A {@code String} variable to store the value of
	 * {@code policyCombiningAlgo} attribute of the {@code PolicySet} instance
	 * to be created.
	 */
	private String policyCombiningAlgorithm = null;
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code PolicySet} instance. By
	 * default it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Sets the {@code daoPolicySet} property to the {@code PolicySetDAO}
	 * argument.
	 * 
	 * @param daoPolicySet
	 */
	public void setDaoPolicySet(PolicySetDAO daoPolicySet) {
		this.daoPolicySet = daoPolicySet;
		log.debug("Set  daoPolicySet: " + daoPolicySet);

	}

	/**
	 * Sets the {@code daoTarget} property to the {@code TargetDAO} argument.
	 * 
	 * @param daoTarget
	 */
	public void setDaoTarget(TargetDAO daoTarget) {
		this.daoTarget = daoTarget;
		log.debug("Set  daoTarget: " + daoTarget);
	}

	/**
	 * Sets the {@code daoPolicy} property to the {@code PolicyDAO} argument.
	 * 
	 * @param daoPolicy
	 */
	public void setDaoPolicy(PolicyDAO daoPolicy) {
		this.daoPolicy = daoPolicy;
		log.debug("Set  daoPolicy: " + daoPolicy);
	}

	/**
	 * Sets the {@code operationFail} property to {@code boolean} argument.
	 * 
	 * @param operationFail
	 */
	public void setOperationFail(boolean operationFail) {
		this.operationFail = operationFail;
		log.debug("Set  operationFail: " + operationFail);
	}

	/**
	 * Sets the {@code selectedPolicySets} property to the {@code List}
	 * argument.
	 * 
	 * @param selectedPolicySets
	 */
	public void setSelectedPolicySets(List<PolicySet> selectedPolicySets) {

		this.selectedPolicySets = selectedPolicySets;
		selectedPolicySetIds = new ArrayList<String>();
		for (int r = 0; r < this.selectedPolicySets.size(); r++) {
			selectedPolicySetIds
					.add(selectedPolicySets.get(r).getPolicySetId());
		}

		log.debug("Set  selectedPolicySets: " + selectedPolicySets);
	}

	/**
	 * Sets the {@code policyCombiningAlgorithm} property to the {@code String}
	 * argument.
	 * 
	 * @param policyCombiningAlgorithm
	 */
	public void setPolicyCombiningAlgorithm(String policyCombiningAlgorithm) {
		this.policyCombiningAlgorithm = policyCombiningAlgorithm;
		log.debug("Set  policyCombiningAlgorithm: " + policyCombiningAlgorithm);
	}

	/**
	 * Sets the {@code selectedPolicies} property to the {@code List} argument.
	 * 
	 * @param selectedPolicies
	 */
	public void setSelectedPolicies(List<Policy> selectedPolicies) {
		this.selectedPolicies = selectedPolicies;
		this.selectedPolicyIds = new ArrayList<String>();
		for (int h = 0; h < this.selectedPolicies.size(); h++) {
			this.selectedPolicyIds.add(selectedPolicies.get(h).getPolicyId());
		}
		log.debug("Set  selectedPolicies: " + selectedPolicies);
	}

	/**
	 * Sets the {@code policySetId} property to the {@code String} argument.
	 * 
	 * @param policySetId
	 */
	public void setPolicySetId(String policySetId) {

		this.policySetId = policySetId;
		log.debug("Set  policySetId: " + policySetId);
	}

	/**
	 * Sets the {@code policySetDescription} property to the {@code String}
	 * argument.
	 * 
	 * @param policySetDescription
	 */
	public void setPolicySetDescription(String policySetDescription) {

		this.policySetDescription = policySetDescription;
		log.debug("Set  policySetDescription: " + policySetDescription);
	}

	/**
	 * Sets the {@code applicableForAll} property to the {@code boolean}
	 * argument.
	 * 
	 * @param applicableForAll
	 */
	public void setApplicableForAll(boolean applicableForAll) {
		this.applicableForAll = applicableForAll;
		log.debug("Set  applicableForAll: " + applicableForAll);
	}

	/**
	 * Sets the {@code selectedTarget} property to the {@code Target} argument.
	 * 
	 * @param selectedTarget
	 */
	public void setSelectedTarget(Target selectedTarget) {
		this.selectedTarget = selectedTarget;
		log.debug("Set  selectedTarget: " + selectedTarget);
	}

	/**
	 * Sets the {@code policySetList} property to the {@code ArrayList}
	 * argument.
	 * 
	 * @param policySetList
	 */
	public void setPolicySetList(ArrayList<PolicySet> policySetList) {
		this.policySetList = policySetList;
		log.debug("Set  policySetList: " + policySetList);
	}

	/**
	 * Sets the {@code policyList} property to the {@code ArrayList} argument.
	 * 
	 * @param policyList
	 */
	public void setPolicyList(ArrayList<Policy> policyList) {
		this.policyList = policyList;
		log.debug("Set  policyList: " + policyList);
	}

	/**
	 * Sets the {@code selectedPolicySetId} property to the {@code String }
	 * argument.
	 * 
	 * @param selectedPolicySetId
	 */
	public void setSelectedPolicySetId(String selectedPolicySetId) {
		this.selectedPolicySetId = selectedPolicySetId;
		log.debug("Set  selectedPolicySetId: " + selectedPolicySetId);
	}

	/**
	 * Sets the {@code selectedPolicyId} property to the {@code String}
	 * argument.
	 * 
	 * @param selectedPolicyId
	 */
	public void setSelectedPolicyId(String selectedPolicyId) {
		this.selectedPolicyId = selectedPolicyId;
		log.debug("Set  selectedPolicyId: " + selectedPolicyId);
	}

	/**
	 * Sets the {@code policyCombiningAlgorithms} property to the {@code List}
	 * argument.
	 * 
	 * @param policyCombiningAlgorithms
	 */
	public void setPolicyCombiningAlgorithms(
			List<String> policyCombiningAlgorithms) {
		this.policyCombiningAlgorithms = policyCombiningAlgorithms;
		log.debug("Set  policyCombiningAlgorithms: "
				+ policyCombiningAlgorithms);
	}

	/**
	 * Sets the {@code targetList} property to the {@code ArrayList} argument.
	 * 
	 * @param targetList
	 */
	public void setTargetList(ArrayList<Target> targetList) {
		this.targetList = targetList;
		log.debug("Set  targetList: " + targetList);
	}

	/**
	 * Sets the {@code selectedPolicySetIds} property to the {@code ArrayList}
	 * argument.
	 * 
	 * @param selectedPolicySetIds
	 */
	public void setSelectedPolicySetIds(ArrayList<String> selectedPolicySetIds) {
		this.selectedPolicySetIds = selectedPolicySetIds;
		log.debug("Set  selectedPolicySetIds: " + selectedPolicySetIds);
	}

	/**
	 * Sets the {@code selectedPolicyIds} property to the {@code ArrayList}
	 * argument.
	 * 
	 * @param selectedPolicyIds
	 */
	public void setSelectedPolicyIds(ArrayList<String> selectedPolicyIds) {
		this.selectedPolicyIds = selectedPolicyIds;
		log.debug("Set  selectedPolicyIds: " + selectedPolicyIds);
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Returns the value of {@code policyCombiningAlgorithm} property.
	 * 
	 * @return policyCombiningAlgorithm
	 */
	public String getPolicyCombiningAlgorithm() {
		log.debug("Get  policyCombiningAlgorithm: " + policyCombiningAlgorithm);
		return policyCombiningAlgorithm;
	}

	/**
	 * Returns the value of {@code targetList} property.
	 * 
	 * @return targetList
	 */
	public ArrayList<Target> getTargetList() {
		log.debug("Getting targetList ");
		return (ArrayList<Target>) daoTarget.selectTarget();

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
	 * Returns the value of {@code daoTarget} property.
	 * 
	 * @return daoTarget
	 */
	public TargetDAO getDaoTarget() {
		log.debug("Get  daoTarget: " + daoTarget);
		return daoTarget;
	}

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
	 * Returns the value of {@code selectedPolicySetIds} property.
	 * 
	 * @return selectedPolicySetIds
	 */
	public ArrayList<String> getSelectedPolicySetIds() {

		log.debug("Get  selectedPolicySetIds: " + selectedPolicySetIds);
		return selectedPolicySetIds;
	}

	/**
	 * Returns the value of {@code selectedPolicyIds} property.
	 * 
	 * @return selectedPolicyIds
	 */
	public ArrayList<String> getSelectedPolicyIds() {
		log.debug("Get  selectedPolicyIds: " + selectedPolicyIds);
		return selectedPolicyIds;
	}

	/**
	 * Returns the value of {@code selectedPolicySetId} property.
	 * 
	 * @return selectedPolicySetId
	 */
	public String getSelectedPolicySetId() {
		log.debug("Get  selectedPolicySetId: " + selectedPolicySetId);
		return selectedPolicySetId;
	}

	/**
	 * Returns the value of {@code selectedPolicyId} property.
	 * 
	 * @return selectedPolicyId
	 */
	public String getSelectedPolicyId() {
		log.debug("Get  selectedPolicyId: " + selectedPolicyId);
		return selectedPolicyId;
	}

	/**
	 * Returns the value of {@code policyCombiningAlgorithms} property.
	 * 
	 * @return policyCombiningAlgorithms
	 */
	public List<String> getPolicyCombiningAlgorithms() {
		log.debug("Get  policyCombiningAlgorithms: "
				+ policyCombiningAlgorithms);
		return policyCombiningAlgorithms;
	}

	/**
	 * Returns {@code FALSE} if a {@code Save} button was pressed otherwise
	 * {@code TRUE}.
	 * 
	 * @return operationFail
	 */
	public boolean isOperationFail() {
		log.debug("Get  operationFail: " + operationFail);
		return operationFail;
	}

	/**
	 * Returns the value of {@code selectedPolicySets} property.
	 * 
	 * @return selectedPolicySets
	 */
	public List<PolicySet> getSelectedPolicySets() {
		log.debug("Get  selectedPolicySets: " + selectedPolicySets);
		return selectedPolicySets;
	}

	/**
	 * Returns the value of {@code selectedPolicies} property.
	 * 
	 * @return selectedPolicies
	 */
	public List<Policy> getSelectedPolicies() {
		log.debug("Get  selectedPolicies: " + selectedPolicies);
		return selectedPolicies;
	}

	/**
	 * Returns the value of {@code policySetId} property.
	 * 
	 * @return policySetId
	 */
	public String getPolicySetId() {

		log.debug("Get  policySetId: " + policySetId);
		return policySetId;
	}

	/**
	 * Returns the value of {@code policySetDescription} property.
	 * 
	 * @return policySetDescription
	 */
	public String getPolicySetDescription() {

		log.debug("Get  policySetDescription: " + policySetDescription);
		return policySetDescription;
	}

	/**
	 * Returns the value of {@code applicableForAll} property.
	 * 
	 * @return applicableForAll
	 */
	public boolean isApplicableForAll() {
		log.debug("Get  applicableForAll: " + applicableForAll);
		return applicableForAll;
	}

	/**
	 * Returns the value of {@code selectedTarget} property.
	 * 
	 * @return selectedTarget
	 */
	public Target getSelectedTarget() {
		log.debug("Get  selectedTarget: " + selectedTarget);
		return selectedTarget;
	}

	/**
	 * Returns the value of {@code policySetList} property.
	 * 
	 * @return policySetList
	 */
	public ArrayList<PolicySet> getPolicySetList() {
		log.debug("Getting  policySetList ");
		return (ArrayList<PolicySet>) daoPolicySet.selectPolicySet();

	}

	/**
	 * Returns the value of {@code policyList} property.
	 * 
	 * @return policyList
	 */
	public ArrayList<Policy> getPolicyList() {
		log.debug("Getting  policyList ");
		return (ArrayList<Policy>) daoPolicy.selectPolicy();

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of adding a new {@code PolicySet} instance.
	 */
	public void cancelAddPolicySet() {
		selectedPolicySets = null;
		selectedPolicies = null;
		this.policyCombiningAlgorithm = null;
		this.policySetDescription = null;
		this.policySetId = null;
		this.applicableForAll = false;
		this.targetList.clear();
		this.selectedTarget = null;
		this.policySetList.clear();
		this.policyList.clear();
		this.selectedPolicyIds.clear();
		this.selectedPolicySetIds.clear();

		RequestContext context = RequestContext.getCurrentInstance();

		this.operationFail = true;
		log.info("Closing dialog.");

		context.closeDialog(this);

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Saves the newly created instance of {@code PolicySet} into the database.
	 */
	public void saveAddPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedPolicySets == null)
			selectedPolicySets = new ArrayList<PolicySet>();
		if (selectedPolicies == null)
			selectedPolicies = new ArrayList<Policy>();
		if (!this.policyCombiningAlgorithm.equals(null)
				&& this.policyCombiningAlgorithm.length() > 0
				&& !policySetDescription.equals(null)
				&& policySetDescription.length() > 0
				&& !this.policySetId.equals(null)
				&& this.policySetId.length() > 0) {
			daoPolicySet.createPolicySet(policySetId, policyCombiningAlgorithm,
					selectedTarget, policySetDescription,
					transformPolicySetToSet(selectedPolicySets),
					transformPolicyToSet(selectedPolicies));
			selectedPolicySets = null;
			selectedPolicies = null;
			this.policyCombiningAlgorithm = null;
			this.policySetDescription = null;
			this.policySetId = null;
			this.applicableForAll = false;
			this.selectedPolicyIds.clear();
			this.selectedPolicySetIds.clear();
			this.selectedPolicies = null;
			this.selectedPolicySets = null;
			this.selectedTarget = null;
			this.operationFail = false;
			log.info("Closing dialog.");
			context.closeDialog(this);
		} else {

			if (this.policyCombiningAlgorithm.equals(null)
					|| this.policyCombiningAlgorithm.length() <= 0) {
				log.info("Algo cannot be empty.");

				context.showMessageInDialog(new FacesMessage(
						FacesMessage.SEVERITY_INFO, "Warning",
						"Algo cannot be empty."));

			} else if (policySetDescription.equals(null)
					|| policySetDescription.length() <= 0) {
				log.info("Description cannot be empty.");

				context.showMessageInDialog(new FacesMessage(
						FacesMessage.SEVERITY_INFO, "Warning",
						"Description cannot be empty."));

			}

			else if (policySetId.equals(null) || policySetId.length() <= 0) {
				log.info("Id cannot be empty.");

				context.showMessageInDialog(new FacesMessage(
						FacesMessage.SEVERITY_INFO, "Warning",
						"Id cannot be empty."));

			}
		}
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Transforms {@code List} of Sub PolicySets to the {@code Set} of Sub
	 * PolicySets.
	 * 
	 * @param selectedPolicySets
	 * @return pSets
	 */
	public Set<PolicySet> transformPolicySetToSet(
			List<PolicySet> selectedPolicySets) {
		Set<PolicySet> pSets = new HashSet<PolicySet>();
		Iterator<PolicySet> iter = selectedPolicySets.iterator();
		while (iter.hasNext()) {
			pSets.add((PolicySet) iter.next());
		}
		return pSets;
	}

	/**
	 * Transforms {@code List} of Sub Policies to the {@code Set} of Sub
	 * Policies.
	 * 
	 * @param selectedPolicies
	 * @return polices
	 */
	public Set<Policy> transformPolicyToSet(List<Policy> selectedPolicies) {
		Set<Policy> polices = new HashSet<Policy>();
		Iterator<Policy> iter = selectedPolicies.iterator();
		while (iter.hasNext()) {
			polices.add((Policy) iter.next());
		}
		return polices;
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */

	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Policy Set Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Policy Set Successfully"));

			this.setOperationFail(true);
		}

	}

}
