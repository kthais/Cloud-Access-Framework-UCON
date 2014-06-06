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
import java.util.List;
import java.util.Set;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.PolicyDAO;
import com.aislab.accesscontrol.core.ui.dao.RuleDAO;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Policy} instance
 * 
 * @author Salman Ahmad Ansari <10besesansari@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 */
@ManagedBean
@SessionScoped
public class AddPolicyController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddPolicyController.class.getName());

	/**
	 * An instance of {@code Policy} used to store the {@code Policy} selected
	 * by the user from the user interface.
	 */
	public Policy selectedPolicy = new Policy();
	/**
	 * An ArrayList of {@code Policy} used to display all the existing
	 * {@code Policy} instances stored in the database.
	 */
	ArrayList<Policy> allPolicy = new ArrayList<Policy>();
	/**
	 * An {@code ArrayList} of {@code Rule}(s) that are applicable for the
	 * {@code Policy} instance to be created.
	 */
	public ArrayList<Rule> ruleList = new ArrayList<Rule>();

	/**
	 * A {@code String} variable to store the value of {@code ruleCombAlgo}
	 * attribute of the {@code Policy} instance to be created.
	 */
	public String appliedAlgo = null;
	/**
	 * A {@code Target} variable to store the value of {@code target} attribute
	 * of the {@code Policy} instance to be created.
	 */
	public Target appliedTarget = null;
	/**
	 * A {@code String} variable to store the value of {@code policyId}
	 * attribute of the {@code Policy} instance to be created.
	 */
	public String name = null;
	/**
	 * A {@code String} variable to store the value of {@code description}
	 * attribute of the {@code Policy} instance to be created.
	 */
	public String description = null;
	/**
	 * An {@code ArrayList} variable used to get all the available {@code Rule}
	 * instances stored in the database.
	 */
	ArrayList<Rule> allRule = new ArrayList<Rule>();
	/**
	 * An {@code ArrayList} variable used to get all the available
	 * {@code Target} instances stored in the database.
	 */
	ArrayList<Target> allTarget = new ArrayList<Target>();

	/**
	 * A {@code List} variable used to get all the available rule combining
	 * algorithms.
	 */
	List<String> algorithmList = Arrays.asList("First applicable",
			"Deny overrides", "Ordered deny overrides", "Permit overrides",
			"Ordered permit overrides");

	/**
	 * An instance of {@code PolicyDAO} for using methods to access data related
	 * to {@code Policy}
	 */
	PolicyDAO daoPolicy = new PolicyDAO();
	/**
	 * An instance of {@code RuleDAO} for using methods to access data related
	 * to {@code Rule}
	 */
	RuleDAO daoRule = new RuleDAO();
	/**
	 * An instance of {@code TargetDAO} for using methods to access data related
	 * to {@code Target}
	 */
	TargetDAO daoTarget = new TargetDAO();

	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Policy} instance. By default
	 * it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;

	/**
	 * A {@code String} variable to store the value of {@code fineLevels} of a
	 * policy
	 */
	public String fineLevels;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Reinitialize all the local variables
	 */
	void init() {
		daoPolicy = new PolicyDAO();
		selectedPolicy = new Policy();
		allPolicy = new ArrayList<Policy>();
		ruleList = null;
		appliedAlgo = null;
		appliedTarget = null;
		name = null;
		description = null;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
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
	 * Sets the {@code allTarget} property to the {@code ArrayList} argument.
	 * 
	 * @param allTarget
	 */
	public void setAllTarget(ArrayList<Target> allTarget) {
		this.allTarget = allTarget;
		log.debug("Set  allTarget: " + allTarget);
	}

	/**
	 * Sets the {@code allRule} property to the {@code ArrayList} argument.
	 * 
	 * @param allRule
	 */
	public void setAllRule(ArrayList<Rule> allRule) {
		this.allRule = allRule;
		log.debug("Set  allRule: " + allRule);
	}

	/**
	 * Sets the {@code name} property to the {@code String} argument.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
		log.debug("Set  name: " + name);
	}

	/**
	 * Sets the {@code description} property to the {@code String } argument.
	 * 
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
		log.debug("Set  description: " + description);
	}

	/**
	 * Sets the {@code dao} property to the {@code PolicyDAO} argument.
	 * 
	 * @param daoTarget
	 */
	public void setDaoPolicy(PolicyDAO daoPolicy) {
		this.daoPolicy = daoPolicy;
		log.debug("Set  daoPolicy: " + daoPolicy);
	}

	/**
	 * Sets the {@code selectedPolicy} property to the {@code Policy} argument.
	 * 
	 * @param selectedPolicy
	 */
	public void setSelectedPolicy(Policy selectedPolicy) {
		this.selectedPolicy = selectedPolicy;
		log.debug("Set  selectedPolicy: " + selectedPolicy);
	}

	/**
	 * Sets the {@code daoRule} property to the {@code RuleDAO} argument.
	 * 
	 * @param daoRule
	 */
	public void setDaoRule(RuleDAO daoRule) {
		this.daoRule = daoRule;
		log.debug("Set  daoRule: " + daoRule);
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
	 * Sets the {@code allPolicy} property to the {@code ArrayList} argument.
	 * 
	 * @param allPolicy
	 */
	public void setAllPolicy(ArrayList<Policy> allPolicy) {
		this.allPolicy = allPolicy;
		log.debug("Set  allPolicy: " + allPolicy);
	}

	/**
	 * Sets the {@code ruleList} property to the {@code ArrayList} argument.
	 * 
	 * @param ruleList
	 */
	public void setRuleList(ArrayList<Rule> ruleList) {
		this.ruleList = ruleList;
		log.debug("Set  ruleList: " + ruleList);
	}

	/**
	 * Sets the {@code appliedAlgo} property to the {@code String} argument.
	 * 
	 * @param appliedAlgo
	 */
	public void setAppliedAlgo(String appliedAlgo) {
		this.appliedAlgo = appliedAlgo;
		log.debug("Set  appliedAlgo: " + appliedAlgo);
	}

	/**
	 * Sets the {@code appliedtTarget} property to the {@code Target} argument.
	 * 
	 * @param appliedtTarget
	 */
	public void setAppliedTarget(Target appliedtTarget) {
		this.appliedTarget = appliedtTarget;
		log.debug("Set  appliedTarget: " + appliedTarget);
	}

	/**
	 * Sets the {@code algorithmList} property to the {@code List} argument.
	 * 
	 * @param algorithmList
	 */
	public void setAlgorithmList(List<String> algorithmList) {
		this.algorithmList = algorithmList;
		log.debug("Set  algorithmList: " + algorithmList);
	}

	/**
	 * Sets the value of Fine Levels
	 * 
	 * @param fineLevels
	 */
	public void setFineLevels(String fineLevels) {
		this.fineLevels = fineLevels;
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
	 * Returns the value of {@code Target} property.
	 * 
	 * @return allTarget
	 */
	public ArrayList<Target> getAllTarget() {
		log.debug("Getting allTarget  ");
		return (ArrayList<Target>) daoTarget.selectTarget();

	}

	/**
	 * Returns the value of {@code allRule} property.
	 * 
	 * @return allRule
	 */
	public ArrayList<Rule> getAllRule() {
		log.debug("Getting  allRule");
		return (ArrayList<Rule>) daoRule.selectRule();
	}

	/**
	 * Returns the value of {@code name} property.
	 * 
	 * @return name
	 */
	public String getName() {
		log.debug("Get  name: " + name);
		return name;
	}

	/**
	 * Returns the value of {@code description} property.
	 * 
	 * @return description
	 */
	public String getDescription() {
		log.debug("Get  description: " + description);
		return description;
	}

	/**
	 * Returns the value of fineLevels
	 * 
	 * @return fineLevels
	 */
	public String getFineLevels() {
		return fineLevels;
	}

	/**
	 * Returns the value of {@code dao} property.
	 * 
	 * @return dao
	 */
	public PolicyDAO getDaoPolicy() {
		log.debug("Get  daoPolicy: " + daoPolicy);
		return daoPolicy;
	}

	/**
	 * Returns the value of {@code daoRule} property.
	 * 
	 * @return daoRule
	 */
	public RuleDAO getDaoRule() {
		log.debug("Get  daoRule: " + daoRule);
		return daoRule;
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
	 * Returns the value of {@code selectedPolicy} property.
	 * 
	 * @return selectedPolicy
	 */
	public Policy getSelectedPolicy() {
		log.debug("Get  selectedPolicy: " + selectedPolicy);
		return selectedPolicy;
	}

	/**
	 * Returns the value of {@code allPolicy} property.
	 * 
	 * @return allPolicy
	 */
	public ArrayList<Policy> getAllPolicy() {
		log.debug("Getting  allPolicy ");
		return (ArrayList<Policy>) daoPolicy.selectPolicy();
	}

	/**
	 * Returns the value of {@code ruleList} property.
	 * 
	 * @return ruleList
	 */
	public ArrayList<Rule> getRuleList() {
		log.debug("Get  ruleList: " + ruleList);
		return ruleList;
	}

	/**
	 * Returns the value of {@code } property.
	 * 
	 * @return algorithmList
	 */
	public List<String> getAlgorithmList() {
		log.debug("Get  algorithmList: " + algorithmList);
		return algorithmList;
	}

	/**
	 * Returns the value of {@code } property.
	 * 
	 * @return appliedTarget
	 */
	public Target getAppliedTarget() {
		if (selectedPolicy != null && selectedPolicy.getTarget() != null) {
			appliedTarget = daoPolicy.selectTarget(selectedPolicy.getTarget()
					.getPkTarget());
		}
		log.debug("Get  appliedTarget: " + appliedTarget);

		return appliedTarget;
	}

	/**
	 * Returns the value of {@code appliedAlgo} property.
	 * 
	 * @return appliedAlgo
	 */
	public String getAppliedAlgo() {
		if (selectedPolicy != null) {
			log.debug("Get  appliedAlgo: " + selectedPolicy.getRuleCombAlgo());
			return selectedPolicy.getRuleCombAlgo();
		}
		log.debug("Get  appliedAlgo: " + null);
		return null;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Saves the newly created instance of {@code Policy} into the database.
	 */
	public void saveAddPolicy() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (this.name == null) {
			context.execute("noNameDialog.show()");

		}
		if (this.description == null) {
			context.execute("noDescriptionDialog.show()");

		}
		// //Ensuring that the Rule Combining Algorithm of the Policy is
		// provided by the User
		if (this.appliedAlgo == null
				|| this.appliedAlgo.equals("Select Rule Combining Algorithm ")) {
			context.execute("noRuleCombDialog.show()");

		}
		int levels = Integer.parseInt(fineLevels);

		if (levels != ruleList.size())
			context.execute("fineLevelMisMatch.show()");
		else if (this.appliedAlgo != null && this.name != null
				&& this.description != null)
		// Casting arrayList into Set, as <code>createPolicy</code> method only
		// accepts Set
		{
			Set<Rule> rules = new HashSet<Rule>(ruleList);
			daoPolicy.createPolicy(name, appliedAlgo, appliedTarget,
					description, rules);
			// Reinitializing all the local variables, after storing the newly
			// created Policy
			ruleList.clear();
			init();

			this.operationFail = false;
			log.info("Closing dialog.");

			context.closeDialog(this);

		}
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of adding a new {@code Policy} instance.
	 */
	public void cancelAddPolicy() {
		// Reinitializing before returning to the homepage
		init();
		RequestContext context = RequestContext.getCurrentInstance();
		this.operationFail = true;
		log.info("Closing dialog.");

		context.closeDialog(this);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Policy Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Policy Successfully"));
			this.setOperationFail(true);
		}

	}
}
