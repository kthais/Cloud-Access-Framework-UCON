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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;
import org.primefaces.event.NodeSelectEvent;
import org.primefaces.model.DefaultTreeNode;
import org.primefaces.model.TreeNode;

import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.entities.Apply;
import com.aislab.accesscontrol.core.entities.AttributeDesignator;
import com.aislab.accesscontrol.core.entities.AttributeValue;
import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.entities.Expression;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.ui.dao.ActionAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ConditionDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectDAO;
import com.aislab.accesscontrol.core.ui.util.XACMLConstants;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code Condition}
 * 
 * @author Salman Ansari <10besesansari@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class AddCondition implements Serializable {

	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddCondition.class.getName());

	/**
	 * A boolean operator to check the valid addition method for condition
	 * 
	 */
	boolean operationFail = true;

	/**
	 * A static variable for serial version of class
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * An instance of TreeNode class for checking the root Node
	 * 
	 */
	private TreeNode root;

	/**
	 * An instance of TreeNode class for checking the current selected Node
	 * 
	 */
	private TreeNode selectedNode;

	/**
	 * An instance of {@code ConditionDAO} for using methods to access data
	 * related to {@code Condition}
	 */
	ConditionDAO testDAO = new ConditionDAO();

	/**
	 * An ArrayList of {@code AddCondition} used to store all newly created
	 * Nodes.
	 */
	ArrayList<TreeNode> newNode = new ArrayList<TreeNode>();

	/**
	 * An ArrayList of {@code Condition} used to store all the created apply's
	 * for a condition.
	 */
	ArrayList<Apply> createdApply = new ArrayList<Apply>();

	/**
	 * An ArrayList of {@code Condition} used to store all the created
	 * expressions for a condition.
	 */
	ArrayList<Expression> createdExpression = new ArrayList<Expression>();

	/**
	 * A List of {@code Condition} used to display Number of Arguments for the
	 * Function.
	 * 
	 */
	List<String> arguments = Arrays.asList("1", "2");

	/**
	 * A {@code String} variable to store the value of selected number of
	 * arguments of the function.
	 * 
	 */
	private String selectedNumber;

	/**
	 * A List of {@code Condition} used to display the available XACML data
	 * types
	 * 
	 */
	List<String> dataType = Arrays.asList("String", "boolean", "integer",
			"double", "time", "date", "dateTime", "dayTimeDuration", "anyURI",
			"dnsName");

	/**
	 * A List of {@code Condition} used to store Function ID
	 * 
	 */
	List<String> functionID = new ArrayList<String>();

	/**
	 * A List of {@code String} used to store Available Designator ID
	 * 
	 */
	List<String> designatorAvailableID = new ArrayList<String>();

	/**
	 * A List of {@code Condition} used to display One argument function list
	 * 
	 */
	List<String> functionOneArg = Arrays
			.asList("urn:oasis:names:tc:xacml:1.0:function:integer-abs",
					"urn:oasis:names:tc:xacml:1.0:function:double-abs",
					"urn:oasis:names:tc:xacml:1.0:function:round",
					"urn:oasis:names:tc:xacml:1.0:function:floor",
					"urn:oasis:names:tc:xacml:1.0:function:string-normalize-space",
					"urn:oasis:names:tc:xacml:1.0:function:string-normalize-to-lower-case",
					"urn:oasis:names:tc:xacml:1.0:function:double-to-integer",
					"urn:oasis:names:tc:xacml:1.0:function:integer-to-double",
					"urn:oasis:names:tc:xacml:1.0:function:not",
					"urn:oasis:names:tc:xacml:2.0:function:url-string-concatenate",
					"urn:oasis:names:tc:xacml:1.0:function:String-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:boolean-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:double-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:time-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:dateTime-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:date-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:dateTimeDuration-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:anyURI-one-and-only",
					"urn:oasis:names:tc:xacml:1.0:function:dnsName-one-and-only");

	/**
	 * A {@code String} variable to store the value of condition description.
	 * 
	 */
	private String condDescription = null;

	/**
	 * A {@code Condition} variable to store the value of Condition.
	 * 
	 */
	private Condition cond = new Condition();

	/**
	 * A {@code Apply} variable to store the first Apply created under the
	 * condition i-e, the root of all other Apply(s), Designator(s), and
	 * Value(s).
	 */
	private Apply rootApply;

	/**
	 * A {@code Apply} variable to store the newly created Apply in the
	 * condition.
	 */
	private Apply apply = null;

	/**
	 * A {@code String} variable to store the value of apply function ID
	 * 
	 */
	private String applyFuncId = "String";

	/**
	 * A {@code String} variable to store the value of apply function
	 * description
	 * 
	 */
	private String applyDesc;

	/**
	 * A {@code String} variable to store the value of apply function type
	 * 
	 */
	private String applyType = null;

	/**
	 * A {@code String} variable to store the value of Designator function ID
	 * 
	 */
	private String designatorId;

	/**
	 * A {@code String} variable to store the value of Attribute Designator
	 * function ID
	 * 
	 */
	private String attributeType;

	/**
	 * A {@code String} variable to store the value of Attribute added
	 * 
	 */
	private String attributeValue;

	/**
	 * A {@code String} variable to store the data type of added value
	 * 
	 */
	private String valueType;

	private String attributeID;
	private List<String> availableAttributeID = new ArrayList<String>();
	private List<Subject> subjList;
	private List<Resource> resList;
	private List<Action> actList;
	private List<Environment> envList;
	List<String> designatorType = Arrays.asList("Subject", "Action",
			"Resource", "Environment");
	private boolean applyButton = false;
	private boolean designatorButton = true;
	private boolean valueButton = true;
	List<String> numberOfArguments = new ArrayList<String>();
	List<String> addedArguments = new ArrayList<String>();
	List<String> addedDataTypes = new ArrayList<String>();

	public boolean isApplyButton() {
		if ((selectedNode.getData().toString().startsWith("Condition") && createdApply
				.size() == 0)
				|| selectedNode.getData().toString().startsWith("Apply"))
			applyButton = false;
		else
			applyButton = true;
		return applyButton;
	}

	public boolean isDesignatorButton() {
		if (selectedNode.getData().toString().startsWith("Apply"))
			designatorButton = false;
		else
			designatorButton = true;
		return designatorButton;
	}

	public boolean isValueButton() {
		if (selectedNode.getData().toString().startsWith("Apply"))
			valueButton = false;
		else
			valueButton = true;
		return valueButton;
	}

	public void setApplyButton(boolean applyButton) {
		this.applyButton = applyButton;
	}

	public void setDesignatorButton(boolean designatorButton) {
		this.designatorButton = designatorButton;
	}

	public void setValueButton(boolean valueButton) {
		this.valueButton = valueButton;
	}

	public List<String> getDesignatorType() {
		return designatorType;
	}

	public void setDesignatorType(List<String> designatorType) {
		this.designatorType = designatorType;
	}

	public List<String> getAvailableAttributeID() {
		return availableAttributeID;
	}

	public void setAvailableAttributeID(List<String> availableAttributeID) {
		this.availableAttributeID = availableAttributeID;
	}

	public String getAttributeID() {
		return attributeID;
	}

	public void setAttributeID(String attributeID) {
		this.attributeID = attributeID;
	}

	public List<Subject> getSubjList() {
		return subjList;
	}

	public List<Resource> getResList() {
		return resList;
	}

	public List<Action> getActList() {
		return actList;
	}

	public List<Environment> getEnvList() {
		return envList;
	}

	public void setSubjList(List<Subject> subjList) {
		this.subjList = subjList;
	}

	public void setResList(List<Resource> resList) {
		this.resList = resList;
	}

	public void setActList(List<Action> actList) {
		this.actList = actList;
	}

	public void setEnvList(List<Environment> envList) {
		this.envList = envList;
	}

	/************************************************** Setter Methods *****************************************/

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
	 * Sets the {@code designatorAvailableID} property to {@code List<String>}
	 * argument.
	 * 
	 * @param designatorAvailableID
	 */
	public void setDesignatorAvailableID(List<String> designatorAvailableID) {
		this.designatorAvailableID = designatorAvailableID;
	}

	/**
	 * Sets the {@code dataType} property to {@code List<String>} argument.
	 * 
	 * @param dataType
	 */
	public void setDataType(List<String> dataType) {
		this.dataType = dataType;
		log.debug("Set  dataType: " + dataType);
	}

	/**
	 * Sets the {@code attributeValue} property to {@code String} argument.
	 * 
	 * @param attributeValue
	 */
	public void setAttributeValue(String attributeValue) {
		this.attributeValue = attributeValue;
		log.debug("Set  attributeValue: " + attributeValue);
	}

	/**
	 * Sets the {@code valueType} property to {@code String} argument.
	 * 
	 * @param valueType
	 */
	public void setValueType(String valueType) {
		this.valueType = valueType;
		log.debug("Set  valueType: " + valueType);
	}

	/**
	 * Sets the {@code designatorId} property to {@code String} argument.
	 * 
	 * @param designatorId
	 */
	public void setDesignatorId(String designatorId) {
		this.designatorId = designatorId;
		System.out.println("**** Setting Designator ID *****");
		log.debug("Set  designatorId: " + designatorId);
		populateAvailableAttributeID();
	}

	/**
	 * Sets the {@code selectedNode} property to {@code String} argument.
	 * 
	 * @param selectedNode
	 */
	public void setSelectedNode(TreeNode selectedNode) {
		this.selectedNode = selectedNode;
		log.debug("Set  selectedNode: " + selectedNode);
	}

	/**
	 * Sets the {@code applyType} property to {@code String} argument.
	 * 
	 * @param applyType
	 */
	public void setApplyType(String applyType) {
		this.applyType = applyType;
		log.debug("Set  applyType: " + applyType);
		populateFunctionId();
	}

	/**
	 * Sets the {@code applyDesc} property to {@code String} argument.
	 * 
	 * @param applyDesc
	 */
	public void setApplyDesc(String applyDesc) {
		this.applyDesc = applyDesc;
		log.debug("Set  applyDesc: " + applyDesc);
	}

	/**
	 * Sets the {@code applyFuncId} property to {@code String} argument.
	 * 
	 * @param applyFuncId
	 */
	public void setApplyFuncId(String applyFuncId) {
		this.applyFuncId = applyFuncId;
		log.debug("Set  applyFuncId: " + applyFuncId);
	}

	/**
	 * Sets the {@code condDescription} property to {@code String} argument.
	 * 
	 * @param condDescription
	 */
	public void setCondDescription(String condDescription) {
		this.condDescription = condDescription;
		log.debug("Set  condDescription: " + condDescription);
	}

	/**
	 * Sets the {@code arguments} property to {@code List<String>} argument.
	 * 
	 * @param arguments
	 */
	public void setArguments(List<String> arguments) {
		this.arguments = arguments;
		log.debug("Set  arguments: " + arguments);
	}

	/**
	 * Sets the {@code functionID} property to {@code List<String>} argument.
	 * 
	 * @param functionID
	 */
	public void setFunctionID(List<String> functionID) {
		this.functionID = functionID;
		log.debug("Set  functionID: " + functionID);
	}

	/**
	 * Sets the {@code selectedNumber} property to {@code String} argument.
	 * 
	 * @param selectedNumber
	 */
	public void setSelectedNumber(String selectedNumber) {
		this.selectedNumber = selectedNumber;
		log.debug("Set  selectedNumber: " + selectedNumber);
		populateFunctionId();
	}

	/**
	 * Sets the {@code attributeType} property to {@code String} argument.
	 * 
	 * @param attributeType
	 */
	public void setAttributeType(String attributeType) {
		this.attributeType = attributeType;
		System.out.println("Attribute Type Setting, after first selection!!!");
		log.debug("Set  attributeType: " + attributeType);
		availableAttributeID.clear();
		populateAvailableDesignatorID();
	}

	/**
	 * Sets the {@code root} property to {@code TreeNode} argument.
	 * 
	 * @param root
	 */
	public void setRoot(TreeNode root) {
		this.root = root;
		log.debug("Set  root: " + root);
	}

	/**
	 * Sets the {@code testDAO} property to {@code ConditionDAO} argument.
	 * 
	 * @param testDAO
	 */
	public void setTestDAO(ConditionDAO testDAO) {
		this.testDAO = testDAO;
		log.debug("Set  testDAO: " + testDAO);
	}

	/**
	 * Sets the {@code newNode} property to {@code ArrayList<TreeNode>}
	 * argument.
	 * 
	 * @param newNode
	 */
	public void setNewNode(ArrayList<TreeNode> newNode) {
		this.newNode = newNode;
		log.debug("Set  newNode: " + newNode);
	}

	/**
	 * Sets the {@code createdApply} property to {@code ArrayList<Apply>}
	 * argument.
	 * 
	 * @param createdApply
	 */
	public void setCreatedApply(ArrayList<Apply> createdApply) {
		this.createdApply = createdApply;
		log.debug("Set  createdApply: " + createdApply);
	}

	/**
	 * Sets the {@code createdExpression} property to
	 * {@code ArrayList<Expression>} argument.
	 * 
	 * @param createdExpression
	 */
	public void setCreatedExpression(ArrayList<Expression> createdExpression) {
		this.createdExpression = createdExpression;
		log.debug("Set  createdExpression: " + createdExpression);
	}

	/**
	 * Sets the {@code functionOneArg} property to {@code List<String>}
	 * argument.
	 * 
	 * @param functionOneArg
	 */
	public void setFunctionOneArg(List<String> functionOneArg) {
		this.functionOneArg = functionOneArg;
		log.debug("Set  functionOneArg: " + functionOneArg);
	}

	/**
	 * Sets the {@code cond} property to {@code Condition} argument.
	 * 
	 * @param cond
	 */
	public void setCond(Condition cond) {
		this.cond = cond;
		log.debug("Set  cond: " + cond);
	}

	/**
	 * Sets the {@code rootApply} property to {@code rootApply} argument.
	 * 
	 * @param rootApply
	 */
	public void setRootApply(Apply rootApply) {
		this.rootApply = rootApply;
		log.debug("Set  rootApply: " + rootApply);
	}

	/**
	 * Sets the {@code apply} property to {@code Apply} argument.
	 * 
	 * @param apply
	 */
	public void setApply(Apply apply) {
		this.apply = apply;
		log.debug("Set  apply: " + apply);
	}

	/*********************************************** Getter Methods ***********************************/

	/**
	 * Returns the value of {@code dataType} property
	 * 
	 * @return dataType
	 */
	public List<String> getDataType() {
		log.debug("Get  dataType: " + dataType);
		return dataType;
	}

	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public String getAttributeValue() {
		log.debug("Get  attributeValue: " + attributeValue);
		return attributeValue;
	}

	/**
	 * Returns the value of {@code valueType} property
	 * 
	 * @return valueType
	 */
	public String getValueType() {
		System.out.println("Here 0 " + valueType);
		log.debug("Get  valueType: " + valueType);
		return valueType;
	}

	/**
	 * Returns the value of {@code designatorId} property
	 * 
	 * @return designatorId
	 */
	public String getDesignatorId() {
		log.debug("Get  designatorId: " + designatorId);
		return designatorId;
	}

	/**
	 * Returns the value of {@code condDescription} property
	 * 
	 * @return condDescription
	 */
	public String getCondDescription() {
		log.debug("Get  condDescription: " + condDescription);
		return condDescription;
	}

	/**
	 * Returns the value of {@code applyFuncId} property
	 * 
	 * @return applyFuncId
	 */
	public String getApplyFuncId() {
		log.debug("Get  applyFuncId: " + applyFuncId);
		return applyFuncId;
	}

	/**
	 * Returns the value of {@code applyDesc} property
	 * 
	 * @return applyDesc
	 */
	public String getApplyDesc() {
		log.debug("Get  applyDesc: " + applyDesc);
		return applyDesc;
	}

	/**
	 * Returns the value of {@code applyType} property
	 * 
	 * @return applyType
	 */
	public String getApplyType() {
		log.debug("Get  applyType: " + applyType);
		return applyType;
	}

	/**
	 * Returns the value of {@code arguments} property
	 * 
	 * @return arguments
	 */
	public List<String> getArguments() {
		log.debug("Get  operationFail: " + arguments);
		return arguments;
	}

	/**
	 * Returns the value of {@code functionID} property
	 * 
	 * @return functionID
	 */
	public List<String> getFunctionID() {
		log.debug("Get  operationFail: " + functionID);
		return functionID;
	}

	/**
	 * Returns the value of {@code root} property
	 * 
	 * @return root
	 */
	public TreeNode getRoot() {
		root.setExpanded(true);
		log.debug("Get  root: " + root);
		return root;
	}

	/**
	 * Returns the value of {@code dataType} selectedNode
	 * 
	 * @return selectedNode
	 */
	public TreeNode getSelectedNode() {
		if (selectedNode != null)
			selectedNode.setExpanded(true);
		log.debug("Get  selectedNode: " + selectedNode);
		return selectedNode;
	}

	/**
	 * Returns the value of {@code dataType} selectedNumber
	 * 
	 * @return selectedNumber
	 */
	public String getSelectedNumber() {
		log.debug("Get  selectedNumber: " + selectedNumber);
		return selectedNumber;
	}

	/**
	 * Returns the value of {@code attributeType} property
	 * 
	 * @return attributeType
	 */
	public String getAttributeType() {
		log.debug("Get  attributeType: " + attributeType);
		return attributeType;
	}

	/**
	 * Returns the value of {@code testDAO} property
	 * 
	 * @return testDAO
	 */
	public ConditionDAO getTestDAO() {
		log.debug("Get  testDAO: " + testDAO);
		return testDAO;
	}

	/**
	 * Returns the value of {@code newNode} property
	 * 
	 * @return newNode
	 */
	public ArrayList<TreeNode> getNewNode() {
		log.debug("Get  newNode: " + newNode);
		return newNode;
	}

	/**
	 * Returns the value of {@code createdApply} property
	 * 
	 * @return createdApply
	 */
	public ArrayList<Apply> getCreatedApply() {
		log.debug("Get  createdApply: " + createdApply);
		return createdApply;
	}

	/**
	 * Returns the value of {@code createdExpression} property
	 * 
	 * @return createdExpression
	 */
	public ArrayList<Expression> getCreatedExpression() {
		log.debug("Get  createdExpression: " + createdExpression);
		return createdExpression;
	}

	/**
	 * Returns the value of {@code functionOneArg} property
	 * 
	 * @return functionOneArg
	 */
	public List<String> getFunctionOneArg() {
		log.debug("Get  functionOneArg: " + functionOneArg);
		return functionOneArg;
	}

	/**
	 * Returns the value of {@code cond} property
	 * 
	 * @return cond
	 */
	public Condition getCond() {
		log.debug("Get  cond: " + cond);
		return cond;
	}

	/**
	 * Returns the value of {@code rootApply} property
	 * 
	 * @return rootApply
	 */
	public Apply getRootApply() {
		log.debug("Get  rootApply: " + rootApply);
		return rootApply;
	}

	/**
	 * Returns the value of {@code apply} property
	 * 
	 * @return apply
	 */
	public Apply getApply() {
		log.debug("Get  apply: " + apply);
		return apply;
	}

	public List<String> getDesignatorAvailableID() {
		return designatorAvailableID;
	}

	/*****************************************************************************************************/

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
	 * Function used to initialize all member variables It is called whenever
	 * there is a need to reinitialize the data members.
	 */
	public void initialize() {
		newNode = new ArrayList<TreeNode>();
		createdApply = new ArrayList<Apply>();
		numberOfArguments = new ArrayList<String>();
		createdExpression = new ArrayList<Expression>();
		availableAttributeID = new ArrayList<String>();
		numberOfArguments = new ArrayList<String>();
		addedArguments = new ArrayList<String>();
		addedDataTypes = new ArrayList<String>();

		condDescription = null;

		cond = new Condition();
		rootApply = new Apply();
		apply = null;

		applyFuncId = "String";
		applyDesc = null;
		applyType = null;

		designatorId = null;
		attributeType = null;

		attributeValue = null;
		valueType = null;

		root = new DefaultTreeNode("Root", null);
		TreeNode node0 = new DefaultTreeNode("Condition", root);
		selectedNode = node0;

		arguments = Arrays.asList("1", "2");
		selectedNumber = null;

	}

	/**
	 * The function is used to add the new instance of {@code Condition} into
	 * the tree.
	 * 
	 */
	public AddCondition() {
		root = new DefaultTreeNode("Root", null);
		TreeNode node0 = new DefaultTreeNode("Condition", root);
		selectedNode = node0;
	}

	/**
	 * Setting the selected node to the {@code selectedNode} variable.
	 * 
	 * @param event
	 *            the selected Node
	 */
	public void onNodeSelect(NodeSelectEvent event) {
		this.selectedNode = event.getTreeNode();
	}

	/**
	 * Saving the created {@code Apply} and hiding the addApply dialog box.
	 * Activating the main addCondition Dialog.
	 */
	public void saveApply() {
		RequestContext context = RequestContext.getCurrentInstance();
		Apply testApply = new Apply(this.applyDesc, this.applyFuncId);
		if (apply == null) {
			rootApply = testApply;
			apply = testApply;
		} else {
			int count = 0;
			String des = (String) (selectedNode.getData());
			des = des.substring(7);
			while (count < createdApply.size()) {
				if (createdApply.get(count).getApplyId().equals(des)) {
					apply = createdApply.get(count);
					break;
				}
				count++;
			}

			count = 0;
			while (count < createdApply.size()) {
				if (createdApply.get(count).equals(apply)) {
					int arg = Integer.parseInt(addedArguments.get(count));
					arg++;
					addedArguments.set(count, Integer.toString(arg));
					break;
				}
				count++;
			}

			testApply.setApply(apply);
			apply = testApply;
		}

		TreeNode temp = new DefaultTreeNode("Apply: " + this.applyDesc,
				this.selectedNode);
		newNode.add(temp);
		createdApply.add(apply);
		addedArguments.add("0");
		numberOfArguments.add(selectedNumber);
		addedDataTypes.add(applyType);
		applyDesc = null;
		applyFuncId = null;
		applyType = null;
		selectedNumber = null;
		log.info("Apply saved Successfully");

		context.execute("addApplyDialog.hide()");
	}

	/**
	 * Canceling the creation of {@code Apply}, and activating the main
	 * addCondition Dialog.
	 */
	public void cancelApply() {
		RequestContext context = RequestContext.getCurrentInstance();
		applyDesc = null;
		applyFuncId = "String";
		applyType = null;
		selectedNumber = null;
		log.info("Adding Apply was cancelled");
		context.execute("addApplyDialog.hide()");
	}

	/**
	 * Saving the created instance of {@code AttributeDesignator}, and adding it
	 * into the Condition Tree. It hides enables the Main addCondition Dialog by
	 * closing the addDesginator Dialog box.
	 */
	public void saveDesignator() {
		if (this.attributeID.equals("No available Attributes")) {
			RequestContext.getCurrentInstance().openDialog(
					"Please select attribute first.");
			return;
		}
		Expression testDesignator = new AttributeDesignator(this.attributeType,
				this.attributeID, this.valueType);

		testDesignator.setApply(apply);
		RequestContext context = RequestContext.getCurrentInstance();
		TreeNode temp = new DefaultTreeNode("Designator: " + this.designatorId,
				this.selectedNode);
		newNode.add(temp);
		createdExpression.add(testDesignator);

		int count = 0;
		while (count < createdApply.size()) {
			if (createdApply.get(count).equals(apply)) {
				int arg = Integer.parseInt(addedArguments.get(count));
				arg++;
				addedArguments.set(count, Integer.toString(arg));
				break;
			}
			count++;
		}

		attributeType = null;
		designatorId = null;
		attributeID = null;
		log.info("Designator saved Successfully.");

		context.execute("addDesignatorDialog.hide()");
	}

	/**
	 * Canceling the created Designator, and reactivating the addCondition main
	 * dialog, by closing the addDesignator Dialog box.
	 */
	public void cancelDesignator() {
		RequestContext context = RequestContext.getCurrentInstance();

		attributeType = null;
		designatorId = null;
		attributeID = null;

		log.info("Adding designator was cancelled.");
		context.execute("addDesignatorDialog.hide()");
	}

	/**
	 * Saving the created instance of {@code AttributeValue}, and adding it into
	 * the Condition Tree. It hides enables the Main addCoondition dialog by
	 * closing the addValue Dialog box.
	 */
	public void saveValue() {
		Expression testValue = new AttributeValue(this.attributeValue,
				this.valueType);

		testValue.setApply(apply);
		RequestContext context = RequestContext.getCurrentInstance();
		TreeNode temp = new DefaultTreeNode("Value: " + this.attributeValue,
				this.selectedNode);
		newNode.add(temp);
		// testDAO.createExpression(testValue);
		createdExpression.add(testValue);
		attributeValue = null;

		int count = 0;
		while (count < createdApply.size()) {
			if (createdApply.get(count).equals(apply)) {
				int arg = Integer.parseInt(addedArguments.get(count));
				arg++;
				addedArguments.set(count, Integer.toString(arg));
				break;
			}
			count++;
		}

		log.info("Value was saved successfully.");

		context.execute("addValueDialog.hide()");
	}

	/**
	 * Canceling the created value and reactivating the main addCondition page
	 * by closing the addValue Dialog box.
	 */
	public void cancelValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		attributeValue = null;
		log.info("Adding value was cancelled.");
		context.execute("addValueDialog.hide()");
	}

	/**
	 * Saving the created Condition in to the database, and close the Dialog box
	 * for creating Condition
	 * 
	 * @return null
	 */
	public String saveCondition() {

		RequestContext context = RequestContext.getCurrentInstance();
		int count = 0;
		while (count < createdApply.size()) {
			if (!addedArguments.get(count).equals(numberOfArguments.get(count))) {
				context.showMessageInDialog(new FacesMessage(
						FacesMessage.SEVERITY_INFO, "Warning",
						"Expected Argument for Apply: "
								+ numberOfArguments.get(count)
								+ " but contains " + addedArguments.get(count)
								+ " arguments."));
				log.info("Expected Argument for Apply: "
						+ numberOfArguments.get(count) + " but contains "
						+ addedArguments.get(count) + " arguments.");
				return null;
			}
			count++;
		}

		if (this.condDescription == null) {
			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Description cannot be empty."));
			log.info("Saving Condition was unsuccessful");

			return null;
		}

		if (this.apply == null) {

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Apply cannot be empty."));
			log.info("Saving Condition was unsuccessful");

			return null;
		}
		cond = new Condition(rootApply);
		cond.setDescription(condDescription);
		testDAO.createApply(createdApply);
		testDAO.createExpression(createdExpression);
		testDAO.createCondition(cond);

		this.operationFail = false;

		// Reinitialize
		initialize();
		// return "/HomePage?faces-redirect=true";

		context.closeDialog(this);
		log.info("Saving Condition was successful");

		return null;
	}

	/**
	 * Canceling the creation of {@code Condition}, closing the addCondition
	 * dialog box, and returning to the main Condition Page.
	 * 
	 */
	public void cancelCondition() {

		RequestContext context = RequestContext.getCurrentInstance();

		// Reinitialize
		initialize();
		// return "/HomePage?faces-redirect=true";
		log.info("Saving Condition was cancelled.");

		context.closeDialog(this);
	}

	/**
	 * Getting all the available Function IDs for {@code Apply} and storing them
	 * in {@code functionID}
	 */
	public void populateFunctionId() {
		XACMLConstants xacmlConsts = new XACMLConstants();
		ArrayList<String> allFuncs = xacmlConsts.getMatchIds();
		functionID = new ArrayList<String>();
		if (this.applyType != null) {
			if (selectedNumber.equals("1")) {
				for (int t = 0; t < functionOneArg.size(); t++) {
					String fId = functionOneArg.get(t);

					if (fId != null) {
						if ((fId.contains(applyType) || fId.contains(applyType
								.toLowerCase(Locale.ENGLISH)))) {

							functionID.add(fId);
						}
					}

				}
				if (applyType.equals("double")) {
					functionID
							.add("urn:oasis:names:tc:xacml:1.0:function:round");
					functionID
							.add("urn:oasis:names:tc:xacml:1.0:function:floor");
				}
				if (applyType.equals("boolean"))
					functionID.add("urn:oasis:names:tc:xacml:1.0:function:not");
			} else {
				for (int t = 0; t < allFuncs.size(); t++) {
					String fId = allFuncs.get(t);

					if (fId != null) {
						if ((fId.contains(applyType) || fId.contains(applyType
								.toLowerCase(Locale.ENGLISH)))
								&& !functionOneArg.contains(fId)) {

							functionID.add(fId);
						}
					}
				}
				if (applyType.equals("boolean")) {
					functionID.add("urn:oasis:names:tc:xacml:1.0:function:and");
					functionID.add("urn:oasis:names:tc:xacml:1.0:function:or");
				}
			}
		}
	}

	public void populateAvailableDesignatorID() {
		int count;
		designatorAvailableID = new ArrayList<String>();
		;
		System.out.println("Populating Available IDs.");
		if (attributeType.equals("Subject")) {
			subjList = testDAO.getSubject();
			count = subjList.size();
			for (int i = 0; i < count; i++) {
				designatorAvailableID.add(subjList.get(i).getSubjectName());
			}
		} else if (attributeType.equals("Action")) {
			actList = testDAO.getAction();
			count = actList.size();
			for (int i = 0; i < count; i++) {
				designatorAvailableID.add(actList.get(i).getActionName());
			}
		} else if (attributeType.equals("Resource")) {
			resList = testDAO.getResource();
			count = resList.size();
			for (int i = 0; i < count; i++) {
				designatorAvailableID.add(resList.get(i).getResourceName());
			}
		} else if (attributeType.equals("Environment")) {
			envList = testDAO.getEnvironment();
			count = envList.size();
			for (int i = 0; i < count; i++) {
				designatorAvailableID.add(envList.get(i).getEnvironmentName());
			}
		}

	}

	public void populateAvailableAttributeID() {
		int count = 0;
		availableAttributeID = new ArrayList<String>();
		System.out.println("Populating Available Attribute IDs.");
		if (attributeType.equals("Subject")) {
			List<SubjectAttribute> list = null;
			while (count < subjList.size()) {
				if (subjList.get(count).getSubjectName().equals(designatorId)) {
					SubjectAttributeDAO dao = new SubjectAttributeDAO();
					list = dao.selectSubjectAttributes(subjList.get(count)
							.getPkSubject());
					break;
				}
				count++;
			}
			count = 0;
			while (count < list.size()) {
				if (list.get(count).getDataType().equalsIgnoreCase(valueType))
					availableAttributeID.add(list.get(count).getSubjAttrId());
				count++;
			}
		} else if (attributeType.equals("Action")) {
			List<ActionAttribute> list = null;
			while (count < actList.size()) {
				if (actList.get(count).getActionName().equals(designatorId)) {
					ActionAttributeDAO dao = new ActionAttributeDAO();
					list = dao.selectActionAttributes(actList.get(count)
							.getPkAction());
					break;
				}
				count++;
			}
			count = 0;
			while (count < list.size()) {
				if (list.get(count).getDataType().equalsIgnoreCase(valueType))
					availableAttributeID.add(list.get(count).getActAttrId());
				count++;
			}
		} else if (attributeType.equals("Resource")) {
			List<ResourceAttribute> list = null;
			while (count < resList.size()) {
				if (resList.get(count).getResourceName().equals(designatorId)) {
					ResourceAttributeDAO dao = new ResourceAttributeDAO();
					list = dao.selectResourceAttributes(resList.get(count)
							.getPkResource());
					break;
				}
				count++;
			}
			count = 0;
			while (count < list.size()) {
				if (list.get(count).getDataType().equalsIgnoreCase(valueType))
					availableAttributeID.add(list.get(count).getResAttrId());
				count++;
			}

		} else if (attributeType.equals("Environment")) {
			List<EnvironmentAttribute> list = null;
			while (count < envList.size()) {
				if (envList.get(count).getEnvironmentName()
						.equals(designatorId)) {
					EnvironmentAttributeDAO dao = new EnvironmentAttributeDAO();
					list = dao.selectEnvironmentAttributes(envList.get(count)
							.getPkEnvironment());
					break;
				}
				count++;
			}
			count = 0;
			while (count < list.size()) {
				if (list.get(count).getDataType().equalsIgnoreCase(valueType))
					availableAttributeID.add(list.get(count).getEnvAttrId());
				count++;
			}
		}
		if (availableAttributeID.size() == 0)
			availableAttributeID.add("No available Attributes");

	}

	public void addListener() {
		System.out.println("In action listener.");
		int count = 0;
		String des = (String) (selectedNode.getData());
		des = des.substring(7);
		while (count < createdApply.size()) {
			if (createdApply.get(count).getApplyId().equals(des)) {
				apply = createdApply.get(count);
				break;
			}
			count++;
		}
		valueType = addedDataTypes.get(count);
	}

	/**
	 * Showing the success message on the successful creation and insertion of
	 * the Condition into the database.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Condition Successfully"));

			this.setOperationFail(true);
		}

	}
}