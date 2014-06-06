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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Actions;
import com.aislab.accesscontrol.core.entities.Environments;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.PolicySet;
import com.aislab.accesscontrol.core.entities.Resources;
import com.aislab.accesscontrol.core.entities.Subjects;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.PolicyDAO;
import com.aislab.accesscontrol.core.ui.dao.PolicySetDAO;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code PolicySet}.
 * 
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class PolicySetController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(PolicySetController.class.getName());

	/**
	 * An instance of {@code PolicySetDAO} for using methods to access data
	 * related to {@code PolicySet}
	 */
	PolicySetDAO daoPolicySet = new PolicySetDAO();
	/**
	 * An instance of {@code PolicyDAO} for using methods to access data related
	 * to {@code Policy}
	 */
	PolicyDAO daoPolicy = new PolicyDAO();
	/**
	 * A {@code List} variable to provide all the policy combining algorithms
	 * available.
	 */
	private List<String> policyCombiningAlgos = Arrays.asList(
			"First applicable", "Deny overrides", "Only one applicable",
			"Permit overrides", "Ordered permit overrides");

	/**
	 * An instance of {@code PolicySet} used to store the {@code PolicySet}
	 * selected by the user from the user interface.
	 */
	private PolicySet selectedPolicySet;
	/**
	 * An ArrayList of {@code PolicySet} used to display all the existing
	 * {@code PolicySet}s stored in the database.
	 */
	ArrayList<PolicySet> allPolicySet = new ArrayList<PolicySet>();

	/**
	 * An instance of {@code TargetDAO} for using methods to access data related
	 * to {@code Target}
	 */

	TargetDAO targetDao = new TargetDAO();

	/**
	 * A {@code String} variable to store the policyId of a particular
	 * {@code PolicySet} instance.
	 */
	private String policySetId;
	/**
	 * A {@code String} variable to store the description of a particular
	 * {@code PolicySet} instance.
	 */
	private String policySetDescription;
	/**
	 * An ArrayList of {@code Target} used to display all the existing
	 * {@code Target} instances available for associating with a
	 * {@code PolicySet} instance.
	 */
	private ArrayList<Target> policySetTarget = new ArrayList<Target>();
	/**
	 * An instance of {@code Target} used to store the {@code Target} selected
	 * by the user from the user interface.
	 */
	private Target clickedTarget;
	/**
	 * A {@code boolean} variable to check the applicability of policy set.
	 */
	private boolean policySetApplicableForAll = false;
	/**
	 * A {@code List} variable used to store all the selected sub
	 * {@code PolicySet} instances while updating an existing {@code PolicySet}.
	 */
	private List<PolicySet> selectedPolicySets;
	/**
	 * A {@code List} variable used to store all the selected sub {@code Policy}
	 * instances while updating an existing {@code PolicySet}.
	 */
	private List<Policy> selectedPolicies;
	/**
	 * A {@code String} variable used to store the selected policy combining
	 * algorithm while updating an existing {@code PolicySet}.
	 */
	private String selectedPolicyCombiningAlgo;

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
	 * A {@code String } used to store the policy selected by the user from the
	 * user interface in terms of policy id.
	 */
	private String selectedPolicyId;
	/**
	 * An instance of {@code PolicySet} used to store the sub {@code PolicySet}
	 * selected by the user from the user interface.
	 */
	private PolicySet selectedSubPolicySet;
	/**
	 * An instance of {@code Policy} used to store the sub {@code Policy}
	 * selected by the user from the user interface.
	 */
	private Policy selectedSubPolicy;

	/**
	 * A boolean variable to check whether any {@code PolicySet} instance is
	 * selected by the user so that the corresponding {@code PolicySet} and
	 * {@code Policy} instance can be added. By default it is set to
	 * {@code TRUE} so that the corresponding add button is disabled while it is
	 * becomes {@code FALSE} if any {@code PolicySet} instance is selected in
	 * the user interface.
	 */
	boolean attrbtn = true;
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Sets the {@code policyCombiningAlgos} property to {@code List} argument.
	 * 
	 * @param policyCombiningAlgos
	 */

	public void setPolicyCombiningAlgos(List<String> policyCombiningAlgos) {
		this.policyCombiningAlgos = policyCombiningAlgos;
		log.debug("Set  policyCombiningAlgos: " + policyCombiningAlgos);
	}

	/**
	 * Sets the {@code selectedSubPolicy} property to {@code Policy} argument.
	 * 
	 * @param selectedSubPolicy
	 */
	public void setSelectedSubPolicy(Policy selectedSubPolicy) {
		this.selectedSubPolicy = selectedSubPolicy;
		log.debug("Set  selectedSubPolicy: " + selectedSubPolicy);
	}

	/**
	 * Sets the {@code selectedPolicyId} property to {@code String} argument.
	 * 
	 * @param selectedPolicyId
	 */
	public void setSelectedPolicyId(String selectedPolicyId) {
		this.selectedPolicyId = selectedPolicyId;
		log.debug("Set  selectedPolicyId: " + selectedPolicyId);
	}

	/**
	 * Sets the {@code selectedPolicySetIds} property to {@code ArrayList}
	 * argument.
	 * 
	 * @param selectedPolicySetIds
	 */
	public void setSelectedPolicySetIds(ArrayList<String> selectedPolicySetIds) {
		this.selectedPolicySetIds = selectedPolicySetIds;
		log.debug("Set  selectedPolicySetIds: " + selectedPolicySetIds);
	}

	/**
	 * Sets the {@code selectedPolicySetId} property to {@code String} argument.
	 * 
	 * @param selectedPolicySetId
	 */
	public void setSelectedPolicySetId(String selectedPolicySetId) {
		this.selectedPolicySetId = selectedPolicySetId;
		log.debug("Set  selectedPolicySetId: " + selectedPolicySetId);
	}

	/**
	 * Sets the {@code selectedPolicyIds} property to {@code ArrayList}
	 * argument.
	 * 
	 * @param selectedPolicyIds
	 */
	public void setSelectedPolicyIds(ArrayList<String> selectedPolicyIds) {
		this.selectedPolicyIds = selectedPolicyIds;
		log.debug("Set  selectedPolicyIds: " + selectedPolicyIds);
	}

	/**
	 * Sets the {@code selectedPolicySet} property to {@code PolicySet}
	 * argument.
	 * 
	 * @param selectedPolicySet
	 */
	public void setSelectedPolicySet(PolicySet selectedPolicySet) {
		if (selectedPolicySet != null) {
			this.selectedPolicySet = selectedPolicySet;
			this.setAttrbtn(false);
		}
		log.debug("Set  selectedPolicySet: " + selectedPolicySet);
	}

	/**
	 * Sets the {@code daoPolicySet} property to {@code PolicySetDAO} argument.
	 * 
	 * @param daoPolicySet
	 */
	public void setDaoPolicySet(PolicySetDAO daoPolicySet) {
		this.daoPolicySet = daoPolicySet;
		log.debug("Set  daoPolicySet: " + daoPolicySet);
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
	 * Sets the {@code selectedSubPolicySet} property to {@code PolicySet}
	 * argument.
	 * 
	 * @param selectedSubPolicySet
	 */
	public void setSelectedSubPolicySet(PolicySet selectedSubPolicySet) {
		this.selectedSubPolicySet = selectedSubPolicySet;
		log.debug("Set  selectedSubPolicySet: " + selectedSubPolicySet);
	}

	/**
	 * Sets the {@code attrbtn} property to {@code boolean} argument.
	 * 
	 * @param attrbtn
	 */
	public void setAttrbtn(boolean attrbtn) {
		this.attrbtn = attrbtn;
		log.debug("Set  attrbtn: " + attrbtn);
	}

	/**
	 * Sets the {@code selectedPolicyCombiningAlgo} property to {@code String}
	 * argument.
	 * 
	 * @param selectedPolicyCombiningAlgo
	 */
	public void setSelectedPolicyCombiningAlgo(
			String selectedPolicyCombiningAlgo) {
		this.selectedPolicyCombiningAlgo = selectedPolicyCombiningAlgo;
		log.debug("Set  selectedPolicyCombiningAlgo: "
				+ selectedPolicyCombiningAlgo);
	}

	/**
	 * Sets the {@code allPolicySet} property to {@code ArrayList} argument.
	 * 
	 * @param allPolicySet
	 */
	public void setAllPolicySet(ArrayList<PolicySet> allPolicySet) {
		this.allPolicySet = allPolicySet;
		log.debug("Set  allPolicySet: " + allPolicySet);
	}

	/**
	 * Sets the {@code targetDao} property to argument.
	 * 
	 * @param targetDao
	 */
	public void setTargetDao(TargetDAO targetDao) {
		this.targetDao = targetDao;
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
	 * Sets the {@code selectedPolicies} property to {@code selectedPolicies}
	 * argument.
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
	 * Sets the {@code selectedPolicySets} property to {@code List} argument.
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
	 * Sets the {@code clickedTarget} property to {@code Target} argument.
	 * 
	 * @param clickedTarget
	 */
	public void setClickedTarget(Target clickedTarget) {
		this.clickedTarget = clickedTarget;
		log.debug("Set  clickedTarget: " + clickedTarget);
	}

	/**
	 * Sets the {@code policySetApplicableForAll} property to {@code boolean}
	 * argument.
	 * 
	 * @param policySetApplicableForAll
	 */
	public void setPolicySetApplicableForAll(boolean policySetApplicableForAll) {
		this.policySetApplicableForAll = policySetApplicableForAll;
		log.debug("Set  policySetApplicableForAll: "
				+ policySetApplicableForAll);
	}

	/**
	 * Sets the {@code policySetId} property to {@code String} argument.
	 * 
	 * @param policySetId
	 */
	public void setPolicySetId(String policySetId) {
		this.policySetId = policySetId;
		log.debug("Set  policySetId: " + policySetId);
	}

	/**
	 * Sets the {@code policySetDescription} property to {@code String}
	 * argument.
	 * 
	 * @param policySetDescription
	 */
	public void setPolicySetDescription(String policySetDescription) {
		this.policySetDescription = policySetDescription;
		log.debug("Set  policySetDescription: " + policySetDescription);
	}

	/**
	 * Sets the {@code policySetTarget} property to {@code ArrayList} argument.
	 * 
	 * @param policySetTarget
	 */
	public void setPolicySetTarget(ArrayList<Target> policySetTarget) {
		this.policySetTarget = policySetTarget;
		log.debug("Set  policySetTarget: " + policySetTarget);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

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
	 * Returns {@code targetDao}
	 * 
	 * @return operationFail
	 */
	public TargetDAO getTargetDao() {
		return targetDao;
	}

	/**
	 * Returns the value of {@code allTargSubjects} property.
	 * 
	 * @return allTargSubjects
	 */
	public ArrayList<Subjects> getAllTargSubjects() {
		if (clickedTarget != null) {
			log.debug("Getting allTargSubjects");
			return (ArrayList<Subjects>) targetDao
					.populateTargetSubjects(clickedTarget.getPkTarget());
		}
		log.debug("Get  allTargSubjects: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code allTargResources} property.
	 * 
	 * @return allTargResources
	 */
	public ArrayList<Resources> getAllTargResources() {
		if (clickedTarget != null) {
			log.debug("Getting allTargResources ");
			return (ArrayList<Resources>) targetDao
					.populateTargetSubjectsResources(clickedTarget
							.getPkTarget());
		}
		log.debug("Get  allTargResources: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code allTargActions} property.
	 * 
	 * @return allTargActions
	 */
	public ArrayList<Actions> getAllTargActions() {
		if (clickedTarget != null) {
			log.debug("Getting  allTargActions ");
			return (ArrayList<Actions>) targetDao
					.populateTargetActions(clickedTarget.getPkTarget());
		}
		log.debug("Get  allTargActions: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code allTargEnvironments} property.
	 * 
	 * @return allTargEnvironments
	 */
	public ArrayList<Environments> getAllTargEnvironments() {
		if (clickedTarget != null) {
			log.debug("Getting  allTargEnvironments ");
			return (ArrayList<Environments>) targetDao
					.populateTargetEnvironments(clickedTarget.getPkTarget());
		}
		log.debug("Get  allTargEnvironments: " + null);
		return null;
	}

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
	 * Returns the value of {@code selectedPolicySetIds} property.
	 * 
	 * @return selectedPolicySetIds
	 */
	public ArrayList<String> getSelectedPolicySetIds() {
		log.debug("Get  selectedPolicySetIds: " + selectedPolicySetIds);
		return selectedPolicySetIds;
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
	 * Returns the value of {@code selectedPolicyIds} property.
	 * 
	 * @return selectedPolicyIds
	 */
	public ArrayList<String> getSelectedPolicyIds() {
		log.debug("Get  selectedPolicyIds: " + selectedPolicyIds);
		return selectedPolicyIds;
	}

	/**
	 * Returns the value of {@code  selectedPolicyId} property.
	 * 
	 * @return selectedPolicyId
	 */
	public String getSelectedPolicyId() {
		log.debug("Get  selectedPolicyId: " + selectedPolicyId);
		return selectedPolicyId;
	}

	/**
	 * Returns the value of {@code selectedSubPolicy} property.
	 * 
	 * @return selectedSubPolicy
	 */
	public Policy getSelectedSubPolicy() {
		log.debug("Get  selectedSubPolicy: " + selectedSubPolicy);
		return selectedSubPolicy;
	}

	/**
	 * Returns the description of {@code Target} associated with the
	 * {@code PolicySet} instance specified by the primary key given as
	 * {@code String} argument.
	 * 
	 * @param pkPolicySet
	 * @return description
	 */
	public String getPSetTarget(String pkPolicySet) {
		Target t = daoPolicySet.getTarget(Long.parseLong(pkPolicySet));
		if (t != null) {
			log.debug("Get  PSetTarget: " + t.getDescription());
			return t.getDescription();
		} else {
			log.debug("Get  PSetTarget: " + "Target Empty");
			return "Target Empty";
		}
	}

	/**
	 * Returns the value of {@code policyCombiningAlgos} property.
	 * 
	 * @return policyCombiningAlgos
	 */
	public List<String> getPolicyCombiningAlgos() {
		log.debug("Get  policyCombiningAlgos: " + policyCombiningAlgos);
		return policyCombiningAlgos;
	}

	/**
	 * Returns {@code FALSE} if an instance of the {@code PolicySet} is selected
	 * by the user otherwise TRUE.
	 * 
	 * @return attrbtn
	 */
	public boolean isAttrbtn() {
		log.debug("Get  attrbtn: " + attrbtn);
		return attrbtn;
	}

	/**
	 * Returns the value of {@code selectedSubPolicySet} property.
	 * 
	 * @return selectedSubPolicySet
	 */
	public PolicySet getSelectedSubPolicySet() {
		log.debug("Get  selectedSubPolicySet: " + selectedSubPolicySet);
		return selectedSubPolicySet;
	}

	/**
	 * Returns the value of {@code selectedPolicyCombiningAlgo} property.
	 * 
	 * @return selectedPolicyCombiningAlgo
	 */
	public String getSelectedPolicyCombiningAlgo() {
		log.debug("Get  selectedPolicyCombiningAlgo: "
				+ selectedPolicyCombiningAlgo);
		return selectedPolicyCombiningAlgo;
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
	 * Returns the value of {@code daoPolicy} property.
	 * 
	 * @return
	 */
	public PolicyDAO getDaoPolicy() {
		log.debug("Get  daoPolicy: " + daoPolicy);
		return daoPolicy;
	}

	/**
	 * Returns the value of {@code allPolicySet} property.
	 * 
	 * @return allPolicySet
	 */
	public ArrayList<PolicySet> getAllPolicySet() {
		log.debug("Getting  allPolicySet ");
		return (ArrayList<PolicySet>) daoPolicySet.selectPolicySet();

	}

	/**
	 * Returns the value of {@code availablePolicySets} property.
	 * 
	 * @return availablePolicySets
	 */
	public ArrayList<PolicySet> getAvailablePolicySets() {
		if (selectedPolicySet != null) {
			log.debug("Getting  availablePolicySets ");
			return (ArrayList<PolicySet>) daoPolicySet
					.getSubPolicySets(selectedPolicySet.getPkPolicySet());
		}
		log.debug("Get  availablePolicySets: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code availablePolicies} property.
	 * 
	 * @return availablePolicies
	 */
	public ArrayList<Policy> getAvailablePolicies() {
		if (selectedPolicySet != null) {
			log.debug("Getting  availablePolicies ");
			return (ArrayList<Policy>) daoPolicySet.getPolicy(selectedPolicySet
					.getPkPolicySet());
		}
		log.debug("Get  availablePolicies: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code policySetId} property.
	 * 
	 * @return policySetId
	 */
	public String getPolicySetId() {
		if (selectedPolicySet != null) {
			log.debug("Get  PolicySetId: " + selectedPolicySet.getPolicySetId());
			return selectedPolicySet.getPolicySetId();
		}
		log.debug("Get  PolicySetId: " + null);

		return null;
	}

	/**
	 * Returns the value of {@code policySetDescription} property.
	 * 
	 * @return policySetDescription
	 */
	public String getPolicySetDescription() {
		if (selectedPolicySet != null) {
			log.debug("Get  PolicySetDescription: "
					+ selectedPolicySet.getDescription());
			return selectedPolicySet.getDescription();
		}
		log.debug("Get  PolicySetDescription: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code selectedPolicySets} property.
	 * 
	 * @return selectedPolicySets
	 */
	public List<PolicySet> getSelectedPolicySets() {
		if (selectedPolicySet != null) {
			log.debug("Getting  selectedPolicySets ");
			return daoPolicySet.getSubPolicySets(selectedPolicySet
					.getPkPolicySet());
		}
		log.debug("Get  selectedPolicySets: " + selectedPolicySets);

		return this.selectedPolicySets;
	}

	/**
	 * Returns the value of {@code selectedPolicies} property.
	 * 
	 * @return selectedPolicies
	 */
	public List<Policy> getSelectedPolicies() {
		if (selectedPolicySet != null) {
			log.debug("Getting selectedPolicies ");
			return daoPolicySet.getPolicy(selectedPolicySet.getPkPolicySet());
		}
		log.debug("Get  selectedPolicies: " + selectedPolicies);

		return this.selectedPolicies;
	}

	/**
	 * Returns the value of {@code policySetTarget} property.
	 * 
	 * @return policySetTarget
	 */
	public ArrayList<Target> getPolicySetTarget() {

		log.debug("Getting PolicySetTarget ");
		return (ArrayList<Target>) targetDao.selectTarget();
	}

	/**
	 * Returns the value of {@code policySetpSets} property.
	 * 
	 * @return policySetpSets
	 */
	public List<PolicySet> getPolicySetpSets() {
		if (selectedPolicySet != null) {
			log.debug("Getting  PolicySetpSets ");
			return daoPolicySet.selectPolicySetsToAdd(selectedPolicySet);
		}
		log.debug("Get  PolicySetpSets: " + null);
		return (List<PolicySet>) null;

	}

	/**
	 * Returns the value of {@code policySetpolicies} property.
	 * 
	 * @return policySetpolicies
	 */
	public ArrayList<Policy> getPolicySetpolicies() {
		if (selectedPolicySet != null) {
			log.debug("Getting  PolicySetpolicies");

			return (ArrayList<Policy>) daoPolicySet
					.selectPoliciesToAdd(this.selectedPolicySet);
		}
		log.debug("Get PolicySetpolicies: " + null);
		return (ArrayList<Policy>) null;

	}

	/**
	 * Returns the value of {@code policySetApplicableForAll} property.
	 * 
	 * @return policySetApplicableForAll
	 */
	public boolean isPolicySetApplicableForAll() {
		log.debug("Get  policySetApplicableForAll: "
				+ policySetApplicableForAll);
		return policySetApplicableForAll;

	}

	/**
	 * Returns the value of {@code policySetPolicyCombiningAlgorithm} property.
	 * 
	 * @return policySetPolicyCombiningAlgorithm
	 */
	public String getPolicySetPolicyCombiningAlgorithm() {

		if (selectedPolicySet != null) {
			log.debug("Get  PolicySetPolicyCombiningAlgorithm: "
					+ selectedPolicySet.getPolicyCombiningAlgo());
			return selectedPolicySet.getPolicyCombiningAlgo();
		}
		log.debug("Get  PolicySetPolicyCombiningAlgorithm: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code clickedTarget} property.
	 * 
	 * @return clickedTarget
	 */
	public Target getClickedTarget() {
		if (selectedPolicySet != null) {
			this.clickedTarget = daoPolicySet.getTarget(selectedPolicySet
					.getPkPolicySet());
		}
		log.debug("Get  clickedTarget: " + clickedTarget);
		return this.clickedTarget;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Opens the {@code /Policy Creation/Policy Set/Add/addNewPolicySet.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of adding a new {@code PolicySet} instance.
	 */
	public String addPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 550);
		options.put("width", 1000);
		options.put("contentHeight", 540);
		options.put("contentWidth", 950);
		options.put("modal", true);
		log.info("Opening  /Policy Creation/Policy Set/Add/addNewPolicySet in a dialog.");

		context.openDialog("/Policy Creation/Policy Set/Add/addNewPolicySet",
				options, null);
		return null;

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of updating an existing {@code PolicySet} instance.
	 */
	public void cancelUpdatePolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Opens the
	 * {@code /Policy Creation/Policy Set/Update/UpdatePolicySetIdAndDescription.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating an existing {@code PolicySet} instance.
	 */
	public void updatePolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 445);
		options.put("width", 765);
		options.put("contentHeight", 430);
		options.put("contentWidth", 750);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Policy Set/Update/UpdatePolicySetIdAndDescription in a dialog.");

		context.openDialog(
				"/Policy Creation/Policy Set/Update/UpdatePolicySetIdAndDescription",
				options, null);
	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Policy Set/Update/UpdatePolicySetSubPoliciesDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the sub policies of an existing
	 * {@code PolicySet} instance.
	 */
	public void updateSubPolicies() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 265);
		options.put("width", 465);
		options.put("contentHeight", 250);
		options.put("contentWidth", 450);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Policy Set/Update/UpdatePolicySetSubPoliciesDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Policy Set/Update/UpdatePolicySetSubPoliciesDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Policy Set/Update/UpdatePolicySetTargetDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the target of an existing {@code PolicySet}
	 * instance.
	 */
	public void updatePSetTargetDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 265);
		options.put("width", 465);
		options.put("contentHeight", 250);
		options.put("contentWidth", 450);
		options.put("modal", true);
		log.info("Opening  /Policy Creation/Policy Set/Update/UpdatePolicySetTargetDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Policy Set/Update/UpdatePolicySetTargetDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Policy Set/Update/UpdatePolicySetSubPSetDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the sub policy set of an existing
	 * {@code PolicySet} instance.
	 */
	public void updateSubPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 195);
		options.put("width", 465);
		options.put("contentHeight", 180);
		options.put("contentWidth", 450);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Policy Set/Update/UpdatePolicySetSubPSetDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Policy Set/Update/UpdatePolicySetSubPSetDialog",
				options, null);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Adds the {@code selectedPolicies} instance to a {@code Policy} instance
	 * specified by {@code selectedPolicySet} property.
	 */
	public void saveUpdatedSubPolicies() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (selectedPolicySet != null) {
			daoPolicySet.addPolicy(selectedPolicySet, this.selectedPolicies);
			this.operationFail = false;

		}
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/**
	 * Saves the updated value of {@code selectedPolicySet} property in the
	 * database.
	 */
	public void saveUpdatedPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (selectedPolicySet != null) {
			daoPolicySet.updatePolicySet(selectedPolicySet.getPkPolicySet(),
					this.policySetId, this.policySetDescription,
					this.selectedPolicyCombiningAlgo, this.clickedTarget);
			this.operationFail = false;
			this.selectedPolicyCombiningAlgo = null;

		}
		log.info("Closing dialog.");

		context.closeDialog(this);

	}

	/**
	 * Adds the {@code clickedTarget} instance to a {@code PolicySet} instance
	 * specified by {@code selectedPolicySet} property.
	 */
	public void saveUpdatedPSetTarget() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedPolicySet != null && this.clickedTarget != null) {
			daoPolicySet.updatePolicySetTarget(
					selectedPolicySet.getPkPolicySet(), this.clickedTarget);
			this.operationFail = false;

		}
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/**
	 * Adds the {@code selectedPolicySets} instance as a sub policy set to a
	 * {@code PolicySet} instance specified by {@code selectedPolicySet}
	 * property.
	 */
	public void saveUpdatedSubPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (selectedPolicySet != null) {
			daoPolicySet.addSubPolicySet(selectedPolicySet,
					(this.selectedPolicySets));
			this.operationFail = false;

		}
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Transforms the {@code List} of {@code Policy} to a {@code Set} of
	 * {@code Policies}
	 * 
	 * @param selectedPolicies
	 * @return policies
	 */
	public Set<Policy> transformToSetPolicies(List<Policy> selectedPolicies) {
		Set<Policy> policies = new HashSet<Policy>();
		for (int y = 0; y < selectedPolicies.size(); y++) {
			policies.add(selectedPolicies.get(y));
		}
		return policies;
	}

	/**
	 * Transforms the {@code List} of {@code Policy} to a {@code Set} of
	 * {@code Policies}
	 * 
	 * @param selectedPolicySets
	 * @return policySets
	 */
	public Set<PolicySet> transformToSetPolicySets(
			List<PolicySet> selectedPolicySets) {
		Set<PolicySet> policySets = new HashSet<PolicySet>();
		for (int y = 0; y < selectedPolicySets.size(); y++) {
			policySets.add(selectedPolicySets.get(y));
		}
		return policySets;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Deletes an instance of {@code PolicySet} stored in
	 * {@code selectedSubPolicySet} property
	 */
	public void deleteSubPolicySet() {
		if (selectedPolicySet != null && this.selectedSubPolicySet != null) {
			daoPolicySet.deleteSubPolicySet(selectedPolicySet.getPkPolicySet(),
					this.selectedSubPolicySet.getPkPolicySet());
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		}
	}

	/**
	 * Deletes an instance of {@code Policy} stored in {@code selectedSubPolicy}
	 * property
	 */
	public void deleteSubPolicies() {
		if (selectedPolicySet != null && this.selectedSubPolicy != null) {
			daoPolicySet.deleteSubPolicies(selectedPolicySet.getPkPolicySet(),
					this.selectedSubPolicy.getPkPolicy());
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		}
	}

	/**
	 * Deletes an instance of {@code Target} corresponding to an instance of
	 * {@code PolicySet} specified by the {@code selectedPolicySet} property.
	 */
	public void deleteTarget() {
		if (selectedPolicySet != null) {
			daoPolicySet.deleteTarget(this.selectedPolicySet.getPkPolicySet());
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		}
	}

	/**
	 * Deletes the instance of {@code Action} stored in
	 * {@code selectedPolicySet} property
	 */
	public void deleteThisPolicySet() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedPolicySet != null) {
			daoPolicySet.deletePolicySet(selectedPolicySet.getPkPolicySet());
			selectedPolicySet = null;
			log.info("Deleted Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		} else {
			context.execute("noPolicySetDialog.show()");
		}
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Successfully"));
			this.setOperationFail(true);
		}

	}

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful update operation.
	 */
	public void showUpdateMessage() {

		if (!isOperationFail()) {
			log.info("Updated Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Updated Successfully"));

			this.setOperationFail(true);
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Disables the buttons for adding {@code PolicySet} and {@code Policy}
	 * instances corresponding to an existing {@code PolicySet} instance.
	 */
	public void onPolicySetUnSelect() {
		this.attrbtn = true;
		this.selectedPolicySet = null;
	}

}
