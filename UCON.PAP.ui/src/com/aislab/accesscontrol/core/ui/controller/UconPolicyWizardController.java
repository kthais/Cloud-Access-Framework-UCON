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

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.jboss.security.xacml.core.model.policy.EffectType;
import org.primefaces.event.FlowEvent;
import org.primefaces.event.NodeSelectEvent;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import org.primefaces.context.RequestContext;
import org.primefaces.model.DefaultTreeNode;
import org.primefaces.model.TreeNode;

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.entities.ActionMatch;
import com.aislab.accesscontrol.core.entities.Actions;
import com.aislab.accesscontrol.core.entities.Apply;
import com.aislab.accesscontrol.core.entities.AttributeAssignment;
import com.aislab.accesscontrol.core.entities.AttributeDesignator;
import com.aislab.accesscontrol.core.entities.AttributeValue;
import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.entities.EnvironmentMatch;
import com.aislab.accesscontrol.core.entities.Environments;
import com.aislab.accesscontrol.core.entities.Expression;
import com.aislab.accesscontrol.core.entities.Obligations;
import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.entities.ResourceMatch;
import com.aislab.accesscontrol.core.entities.Resources;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.entities.SubjectMatch;
import com.aislab.accesscontrol.core.entities.Subjects;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.ActAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionDAO;
import com.aislab.accesscontrol.core.ui.dao.AttributeAssignmentDAO;
import com.aislab.accesscontrol.core.ui.dao.ConditionDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentDAO;
import com.aislab.accesscontrol.core.ui.dao.ObligationsDAO;
import com.aislab.accesscontrol.core.ui.dao.PolicyDAO;
import com.aislab.accesscontrol.core.ui.dao.ResAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceDAO;
import com.aislab.accesscontrol.core.ui.dao.RuleDAO;
import com.aislab.accesscontrol.core.ui.dao.SubAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectDAO;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;
import com.aislab.accesscontrol.core.ui.util.XACMLConstants;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code UCON Policy}
 * 
 * @author Junaid Bin Sarfraz <10besejsarfraz@seecs.edu.pk>
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @version 1.0
 * 
 */

@ManagedBean
@ViewScoped
public class UconPolicyWizardController implements Serializable{
	

	// ////////////////////////////////////////////////////////Obligation

	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(UconPolicyWizardController.class
			.getName());

	/**
	 * An instance of {@code ConditionDAO} for using methods to access data
	 * related to {@code Condition}
	 */
	ConditionDAO conditionDao = new ConditionDAO();
	
	/**
	 * A {@code ArrayList} of type {@code Condition} variable to provide all the
	 * available conditions.
	 */
	ArrayList<Condition> allCondition = new ArrayList<Condition>();
	
	/**
	 * An instance of {@code Condition} used to store the {@code Condition} selected
	 * by the user from the user interface.
	 */
	Condition selectedCondition = null;

	// ////////////////////////////////////////////////////////

	// //////////////////////////////////////////////////////// Add Obligation
	
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;
	
	//asdasdasd
	
	
	/**
	 * An Instance of {@code TreeNode} class for checking the root Node
	 */
	private TreeNode root;
	
	/**
	 * An Instance of {@code TreeNode} class for checking the current selected Node
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
	 * An ArrayList of {@code Condition} used to store Selected number of
	 * Arguments.
	 * 
	 */
	ArrayList<String> number = new ArrayList<String>();

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
			"hexBinary", "base64Binary", "rfc822Name", "x500Name");

	/**
	 * A List of {@code Condition} used to store Function ID
	 * 
	 */
	List<String> functionID = new ArrayList<String>();

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
					"urn:oasis:names:tc:xacml:2.0:function:url-string-concatenate");

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
	 * A {@code String} variable to store the value of Designator function Type
	 * 
	 */
	private String designatorType;
	
	/**
	 * A {@code String} variable to store the value of Attribute Designator
	 * function ID
	 * 
	 */
	private String attributeDesignatorId;

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

	// ////////////////////////////////////////////////////////sasadasd
	/**
	 * A boolean variable GUI property if checked {@code Policy} generated Id includes
	 * 'Pre'
	 */
	private boolean pre;
	/**
	 * A boolean variable GUI property if checked {@code Policy} generated Id includes
	 * 'Pre'
	 */
	private boolean on;
	
	/**
	 * A {@code String} variable to store the Request Interval when {@code on}
	 * Checkbox is selected holds the time in seconds in String format
	 * to be specified in the policy for request Interval for re-evaluation
	 */
	private String reqInterval;

	

	/**
	 * A {@code TargetDAO} Object for making transactions regarding {@code Target} Table
	 * in Database
	 */
	TargetDAO dao = new TargetDAO();
	
	/**
	 * A {@code List} of all Created {@code Target}
	 */
	ArrayList<Target> allTarget = new ArrayList<Target>();
	
	/**
	 * A {@code Target} Object getting the {@code Target} selected on rowSelect 
	 * event of Target dataTable
	 */
	private Target clickedTarget;
	
	/**
	 * A {@code List} of all the {@code Subjects} Added to the selected {@code Target}
	 */
	private ArrayList<Subjects> allTargSubjects = new ArrayList<Subjects>();

	/**
	 * A {@code List} of all the {@code Resources} Added to the selected {@code Target}
	 */
	private ArrayList<Resources> allTargResources = new ArrayList<Resources>();
	
	/**
	 * A {@code List} of all the {@code Actions} Added to the selected {@code Target}
	 */
	private ArrayList<Actions> allTargActions = new ArrayList<Actions>();
	
	/**
	 * A {@code List} of all the {@code Environments} Added to the selected {@code Target}
	 */
	private ArrayList<Environments> allTargEnvironments = new ArrayList<Environments>();
	
	/**
	 * Variables declared for Update Target
	 * 
	 * @return
	 */
	/**
	 * A {@code List} of Match Ids, updated based upon selected Attribute Value when adding
	 * {@code Subject}/{@code Resource}/{@code Action}Action/{@code Environment} to a {@code Target}
	 */
	public static ArrayList<String> matchIds = new ArrayList<String>();
	
	/**
	 * A {@cod String} variable to Get the instance of Match Id Selected in Match Ids DataTable 
	 * when adding {@code Subject}/{@code Resource}/{@code Action}Action/{@code Environment}
	 * to a {@code Target}
	 */
	private String selectedMatchId = null;;
	
	/**
	 * A {@code Subject} variable for getting instance of row selection for available
	 * {@code Subject} in Target.xhtml
	 */
	private Subject addedTargetSubject;
	
	/**
	 * A {@code Resource} variable for getting instance of row selection for available
	 * {@code Resource} in Target.xhtml
	 */
	private Resource addedTargetResource;
	
	/**
	 * A {@code Action} variable for getting instance of row selection for available
	 * {@code Action} in Target.xhtml
	 */
	private Action addedTargetAction;
	
	/**
	 * A {@code Environment} variable for getting instance of row selection for available
	 * {@code Environment} in Target.xhtml
	 */
	private Environment addedTargetEnvironment;
	
	/**
	 * A {@code Subjects} variable that gets the instance of {@code Subjects} selected 
	 * from the list of {@code Subjects} added to a selected {@code Target}
	 */
	private Subjects selectedSubjects;
	
	/**
	 * A {@code Resources} variable that gets the instance of {@code Resources} selected 
	 * from the list of {@code Resources} added to a selected {@code Target}
	 */
	private Resources selectedResources;
	
	/**
	 * A {@code Actions} variable that gets the instance of {@code Actions} selected 
	 * from the list of {@code Actions} added to a selected {@code Target}
	 */
	private Actions selectedActions;
	
	/**
	 * A {@code Environments} variable that gets the instance of {@code Environments} selected 
	 * from the list of {@code Environments} added to a selected {@code Target}
	 */
	private Environments selectedEnvironments;
	
	/**
	 * A {@code boolean} variable that is  Associated with 'Must Be Present'
	 * checkBox when adding new {@code Subject}/{@code Resource}/{@code Action}Action/
	 * {@code Environment} to a {@code Target}
	 */
	private boolean mustBePresent = false;
	
	/**
	 * A {@code String} variable that store the value selected from the list of {@code SubAttValue}
	 */
	private String selectedSubAttValue;
	
	/**
	 * Variable for Description and updated Description of Target
	 */
	
	/**
	 * A {@code String} variable to store the description of {@code Target}
	 */
	private String description;
	
	/**
	 * A {@code String} variable to store the description of Updated {@code Target}
	 */
	private String updatedDescription;
	
	/**
	 * A {@code String} variable to store the id of Updated {@code Target}
	 */
	private String updatedTargetId;
	
	/**
	 * A {@code List} of {@code Object[]} {@code Subjects} that is use for providing the required format
	 * for query of {@code Target} in database
	 */
	List<Object[]> subjListTarg;
	
	/**
	 * A {@code List} of {@code Object[]} {@code Resources} that is use for providing the required format
	 * for query of {@code Target} in database
	 */
	List<Object[]> resListTarg;
	
	/**
	 * A {@code List} of {@code Object[]} {@code Actions} that is use for providing the required format
	 * for query of {@code Target} in database
	 */
	List<Object[]> actListTarg;
	
	/**
	 * A {@code List} of {@code Object[]} {@code Environments} that is use for providing the required format
	 * for query of {@code Target} in database
	 */
	List<Object[]> envListTarg;
	/**
	 * Data Access Object Class Instances for holding database Queries for
	 * Subjects/Resources/Actions/Environments their Attribute Data Access
	 * Objects and the Attribute Values Data Access Objects Instances
	 */
	
	/**
	 * An {@code SubjectDAO} variable for using methods to access data
	 * related to {@code Subject}
	 */
	SubjectDAO daoSubject = new SubjectDAO();
	
	/**
	 * An {@code SubjectAttributeDAO} variable for using methods to access data
	 * related to {@code SubjectAttribute}
	 */
	SubjectAttributeDAO daoSubjectAttribute = new SubjectAttributeDAO();
	
	/**
	 * An {@code SubjectAttributeValueDAO} variable for using methods to access data
	 * related to {@code SubjectAttributeValue}
	 */
	SubAttrValuesDAO daoSubjectAttributeValue = new SubAttrValuesDAO();

	/**
	 * An {@code ResourceDAO} variable for using methods to access data
	 * related to {@code Resource}
	 */
	ResourceDAO daoRes = new ResourceDAO();

	/**
	 * An {@code ResourceAttributeDAO} variable for using methods to access data
	 * related to {@code ResourceAttribute}
	 */
	ResourceAttributeDAO daoResourceAttribute = new ResourceAttributeDAO();
	
	/**
	 * An {@code ResourceAttributeValueDAO} variable for using methods to access data
	 * related to {@code ResourceAttributeValue}
	 */
	ResAttrValuesDAO daoResourceAttributeValue = new ResAttrValuesDAO();

	/**
	 * An {@code ActionDAO} variable for using methods to access data
	 * related to {@code Action}
	 */
	ActionDAO daoAction = new ActionDAO();
	
	/**
	 * An {@code ActionAttributeDAO} variable for using methods to access data
	 * related to {@code ActionAttribute}
	 */
	ActionAttributeDAO daoActionAttribute = new ActionAttributeDAO();
	
	/**
	 * An {@code ActionAttributeValueDAO} variable for using methods to access data
	 * related to {@code ActionAttributeValue}
	 */
	ActAttrValuesDAO daoActionAttributeValue = new ActAttrValuesDAO();

	/**
	 * An {@code EnvironmentDAO} variable for using methods to access data
	 * related to {@code Environment}
	 */
	EnvironmentDAO daoEnv = new EnvironmentDAO();
	
	/**
	 * An {@code EnvironmentAttributeDAO} variable for using methods to access data
	 * related to {@code EnvironmentAttribute}
	 */
	EnvironmentAttributeDAO envattrdao = new EnvironmentAttributeDAO();
	
	/**
	 * An {@code EnvironmentAttributeValueDAO} variable for using methods to access data
	 * related to {@code EnvironmentAttributeValue}
	 */
	EnvAttrValuesDAO envattrvaluesdao = new EnvAttrValuesDAO();

	/**
	 * A {@code Action} variable use to get the selected instance of {@code Action}
	 * in the Action Data Table
	 */
	private Action selectedAction;
	
	/**
	 * A {@code ActionAttribute} variable use to get the selected instance of {@code ActionAttribute}
	 * in the Action Attribute Data Table
	 */
	private ActionAttribute selectedActionAttributes;

	/**
	 * A {@code SubAttrValues} variable that gets the selected instance of the 
	 * {@code SubjectAttributeValue} in the {@code SubjectAttributeValue} Data Table 
	 * Updated when a Value is Selected in the {@code SubjectAttributeValue} Data Table 
	 */
	private SubAttrValues selectedSubValue;
	
	/**
	 * A {@code ResAttrValues} variable that gets the selected instance of the 
	 * {@code ResourceAttributeValue} in the {@code ResourceAttributeValue} Data Table 
	 * Updated when a Value is Selected in the {@code ResourceAttributeValue} Data Table 
	 */
	private ResAttrValues selectedResValue;
	
	/**
	 * A {@code ActAttrValues} variable that gets the selected instance of the 
	 * {@code ActionAttributeValue} in the {@code ActionAttributeValue} Data Table 
	 * Updated when a Value is Selected in the {@code ActionAttributeValue} Data Table 
	 */
	private ActAttrValues selectedActValue;
	
	/**
	 * A {@code EvnAttrValues} variable that gets the selected instance of the 
	 * {@code EnvironmentAttributeValue} in the {@code EnvironmentAttributeValue} Data Table 
	 * Updated when a Value is Selected in the {@code EnvironmentAttributeValue} Data Table 
	 */
	private EnvAttrValues selectedEnvValue;

	// Used to store selected values, and matchIds in memory
	
	/**
	 * An {@code ArrayList} of {@code SubAttrValues} is use to store the {@code SubAttrValues}
	 */
	public ArrayList<SubAttrValues> selectedSubAttrValues = new ArrayList<SubAttrValues>();
	
	/**
	 * An {@code ArrayList} of {@code String} use to store the matchids for each selected
	 * {@code SubAttrValues}
	 */
	public ArrayList<String> selectedSubMatchIds = new ArrayList<String>();

	/**
	 * An {@code ArrayList} of {@code ResAttrValues} is use to store the {@code ResAttrValues}
	 */
	public ArrayList<ResAttrValues> selectedResAttrValues = new ArrayList<ResAttrValues>();
	
	/**
	 * An {@code ArrayList} of {@code String} use to store the matchids for each selected
	 * {@code ResAttrValues}
	 */
	public ArrayList<String> selectedResMatchIds = new ArrayList<String>();

	/**
	 * An {@code ArrayList} of {@code ActAttrValues} is use to store the {@code ActAttrValues}
	 */
	public ArrayList<ActAttrValues> selectedActAttrValues = new ArrayList<ActAttrValues>();
	
	/**
	 * An {@code ArrayList} of {@code String} use to store the matchids for each selected
	 * {@code ActAttrValues}
	 */
	public ArrayList<String> selectedActMatchIds = new ArrayList<String>();

	/**
	 * An {@code ArrayList} of {@code EnvAttrValues} is use to store the {@code EnvAttrValues}
	 */
	public ArrayList<EnvAttrValues> selectedEnvAttrValues = new ArrayList<EnvAttrValues>();

	/**
	 * An {@code ArrayList} of {@code String} use to store the matchids for each selected
	 * {@code EnvAttrValues}
	 */
	public ArrayList<String> selectedEnvMatchIds = new ArrayList<String>();

	// For selection of subjects, resources, environment, action in
	// selectSubject.xhtml ....so on ... selectEnvironment.xhtml
	/**
	 * A {@code Subject} variable that get the selected instance of {@code Subject}
	 * in the {@code Subject} Data Table Subject.xhtml
	 */
	public Subject selectedSubject;
	
	/**
	 * A {@code Resource} variable that get the selected instance of {@code Resource}
	 * in the {@code Resource} Data Table Resource.xhtml
	 */
	private Resource selectedResource;
	
	/**
	 * A {@code Environment} variable that get the selected instance of {@code Environment}
	 * in the {@code Environment} Data Table Environment.xhtml
	 */
	private Environment selectedEnvironment;
	
	/**
	 * A {@code EnvironmentAttribute} variable that get the selected instance of 
	 * {@code EnvironmentAttribute} in the {@code EnvironmentAttribute} Data Table 
	 */
	private EnvironmentAttribute selectedEnvironmentAttribute;
	
	/**
	 * A {@code ResourceAttribute} variable that get the selected instance of 
	 * {@code ResourceAttribute} in the {@code ResourceAttribute} Data Table 
	 */
	public ResourceAttribute selectedResourceAttribute;
	
	/**
	 * An {@code ArrayList} of all {@code Subject}(s) that can be added to a {@code Target}
	 */
	public ArrayList<Subject> targetSubjects = new ArrayList<Subject>();
	
	/**
	 * An {@code ArrayList} of all {@code Resource}(s) that can be added to a {@code Target}
	 */
	public ArrayList<Resource> targetResources = new ArrayList<Resource>();
	
	/**
	 * An {@code ArrayList} of all {@code Action}(s) that can be added to a {@code Target}
	 */
	public ArrayList<Action> targetActions = new ArrayList<Action>();
	
	/**
	 * An {@code ArrayList} of all {@code Environment}(s) that can be added to a {@code Target}
	 */
	public ArrayList<Environment> targetEnvironments = new ArrayList<Environment>();
	
	/**
	 * A {@code SubjectAttribute} variable that is selected from the list of {@code SubjectAttribute}
	 */
	public SubjectAttribute selectedSubjectAttributes;
	
	/**
	 * An {@code ArrayList} of all the {@code SubjectAttribute} that is updated on the selection
	 * of {@code Subject} Data Table
	 */
	public ArrayList<SubjectAttribute> allSubAttributes = new ArrayList<SubjectAttribute>();
	
	/**
	 * An {@code ArrayList} of all the {@code ResourceAttribute} that is updated on the selection
	 * of {@code Resource} Data Table
	 */
	public ArrayList<ResourceAttribute> allResAttributes = new ArrayList<ResourceAttribute>();
	
	/**
	 * An {@code ArrayList} of all the {@code ActionAttribute} that is updated on the selection
	 * of {@code Action} Data Table
	 */
	public ArrayList<ActionAttribute> allActAttributes = new ArrayList<ActionAttribute>();
	
	/**
	 * An {@code ArrayList} of all the {@code EnvironmentAttribute} that is updated on the selection
	 * of {@code Environment} Data Table
	 */
	public ArrayList<EnvironmentAttribute> allEnvAttributes = new ArrayList<EnvironmentAttribute>();
	
	/**
	 * An {@code ArrayList} of all the {@code SubAttrValues} that is updated on the selection
	 * of {@code SubjectAttribute} Data Table
	 */
	public ArrayList<SubAttrValues> allSubValues = new ArrayList<SubAttrValues>();
	
	/**
	 * An {@code ArrayList} of all the {@code ResAttrValues} that is updated on the selection
	 * of {@code ResourceAttribute} Data Table
	 */
	public ArrayList<ResAttrValues> allResValues = new ArrayList<ResAttrValues>();
	
	/**
	 * An {@code ArrayList} of all the {@code ActAttrValues} that is updated on the selection
	 * of {@code ActionAttribute} Data Table
	 */
	public ArrayList<ActAttrValues> allActValues = new ArrayList<ActAttrValues>();
	
	/**
	 * An {@code ArrayList} of all the {@code EnvAttrValues} that is updated on the selection
	 * of {@code EnvironmentAttribute} Data Table
	 */
	public ArrayList<EnvAttrValues> allEnvValues = new ArrayList<EnvAttrValues>();
	
	/**
	 * A {@code boolean} variable that is use for displayinng data in the Subject, Resource
	 * Action and Environment Pages
	 */
	boolean addbtn = true;

	/**
	 * A {@code boolean} operator to check the valid addition method for {@code Condition}
	 */
	boolean opertionFail = true;

	

	

	

	// For Policy
	
	/**
	 * A {@code PolicyDAO} variable for using methods to access data
	 * related to {@code Policy}
	 */
	private PolicyDAO policyDao = new PolicyDAO();
	
	/**
	 * A {@code String} variable use to store the Policy Id
	 */
	private String policyName = null;
	
	/**
	 * A {@code String} variable use to store the Policy Description
	 */
	private String policyDescription = null;
	
	/**
	 * A {@code List} of possible Rule Combining Algortihms
	 */
	private List<String> algorithmList = Arrays.asList("First applicable",
			"Deny overrides", "Ordered deny overrides", "Permit overrides",
			"Ordered permit overrides");
	
	/**
	 * A {@code String} variable use to store the selected Rule Combining Algorithm
	 */
	private String appliedAlgo = null;
	
	
	/**
	 * A {@code boolean} varaible use to check if 
	 * user want to enter preUpdate or not
	 */
	public boolean preUpdateCheckBox;
	
	/**
	 * A {@code boolean} varaible use to check if 
	 * user want to enter onGoingUpdate or not
	 */
	public boolean onGoingUpdateCheckBox;
	
	/**
	 * A {@code boolean} varaible use to check if 
	 * user want to enter postUpdate or not
	 */
	public boolean postUpdateCheckBox;

	

	/**
	 * A {@code String} variable use to store the Attribute Id
	 * for the preUpdate
	 */
	public String preAttrId;
	
	/**
	 * A {@code String} variable use to store the Attribute value
	 * across the Attribute Id for the preUpdate
	 */
	public String preValue;
	
	/**
	 * A {@code List} of {@code AttributeAssignment} to store the 
	 * {@code AttributeAssignment}(s) for preUpdate
	 */
	public List<AttributeAssignment> preValues;

	
	/**
	 * A {@code String} variable use to store the Attribute Id
	 * for the onGoingUpdate
	 */
	public String onGoingAttrId;
	
	/**
	 * A {@code String} variable use to store the Attribute value
	 * across the Attribute Id for the onGoingUpdate
	 */
	public String onGoingValue;
	
	/**
	 * A {@code List} of {@code AttributeAssignment} to store the 
	 * {@code AttributeAssignment}(s) for onGoingUpdate
	 */
	public List<AttributeAssignment> onGoingValues;

	
	/**
	 * A {@code String} variable use to store the Attribute Id
	 * for the postUpdate
	 */
	public String postAttrId;
	
	/**
	 * A {@code String} variable use to store the Attribute value
	 * across the Attribute Id for the postUpdate
	 */
	public String postValue;
	
	/**
	 * A {@code List} of {@code AttributeAssignment} to store the 
	 * {@code AttributeAssignment}(s) for postUpdate
	 */
	public List<AttributeAssignment> postValues;

	/**
	 * A {@code List} of {@code String} to store the possible data types
	 * of the {@code AttributeAssignment}
	 */
	public List<String> dataTypes;

	/**
	 * A {@code AttributeAssignment} variable to store the selected
	 * {@code AttributeAssignment} for preUpdate
	 */
	public AttributeAssignment selectedPreUpdate;
	
	/**
	 * A {@code AttributeAssignment} variable to store the selected
	 * {@code AttributeAssignment} for onGoingUpdate
	 */
	public AttributeAssignment selectedOnGoingUpdate;
	
	/**
	 * A {@code AttributeAssignment} variable to store the selected
	 * {@code AttributeAssignment} for postUpdate
	 */
	public AttributeAssignment selectedPostUpdate;

	/**
	 * A {@code List} of {@code String} that store the Attribute ids 
	 * of preUpdate {@code AttributeAssignment}
	 */
	public List<String> attrIds;
	
	/**
	 * A {@code List} of {@code String} that store the Attribute ids 
	 * of onGoingUpdate {@code AttributeAssignment}
	 */
	public List<String> onGoingAttrIds;
	
	/**
	 * A {@code List} of {@code String} that store the Attribute ids 
	 * of postUpdate {@code AttributeAssignment}
	 */
	public List<String> postAttrIds;

	/**
	 * A {@code List} of {@code String} that stores the Request Time Interval
	 * if the onGoing Checked Box is checked
	 */
	public List<String> onGoingTimes;
	
	/**
	 * A {@code String} variable for storing the onGoing time for request interval
	 * if the onGoing Checked Box is checked
	 */
	public String onGoingTime;

	/**
	 * A {@code boolean} variable use to render the Request Interval Input box
	 */
	private boolean onGoingReqOrUpdate;
	
	/**
	 * A {@code Target} variable use for selection of {@code Target} that
	 * has not null {@code Condition}
	 */
	private Target clickedConditionTarget;
	
	/**
	 * An {@code ArrayList} of {@code Target} that stores all the {@code Target}(s)
	 * that has not null {@code Condition}
	 */
	ArrayList<Target> allNotNullCondTargets;

	/**
	 * A {@code String} variable use to check if the authorization, obligation
	 * or condition is selected from the combo box, default is authorization
	 */
	String abcProperties = "auth";
	
	/**
	 * A {@code boolean} variable use to check if authorization is selected or not,
	 * so that it can be use to render other components in the gui
	 */
	boolean abcPropertiesAuth;
	
	/**
	 * A {@code boolean} variable use to check if obligation is selected or not,
	 * so that it can be use to render other components in the gui
	 */
	boolean abcPropertiesObl;
	
	/**
	 * A {@code boolean} variable use to check if condition is selected or not,
	 * so that it can be use to render other components in the gui
	 */
	boolean abcPropertiesCond;

	/**
	 * An {@code ArrayList} of {@code Target} that has all available {@code Targets}
	 */
	ArrayList<Target> allOblTarget;
	
	/**
	 * A {@code Target} variable use to select {@code Target} from ObligationTarget
	 * data table
	 */
	private Target clickedOblTarget;

	/**
	 * A {@code String} variable that is rendered on the screen with pre - authorization,
	 * obligation or condition depending upon which combo box is selected
	 */
	private String preABC;
	
	/**
	 * A {@code String} variable that is rendered on the screen with onGoing - authorization,
	 * obligation or condition depending upon which combo box is selected
	 */
	private String onGoingABC;
	
	/**
	 * A {@code String} variable that is use to render the legend for pre and On-Going ABC
	 */
	private String propertyABC;

	/**
	 * An {@code ArrayList} of {@code Target} that has {@code Target}(s) that has
	 * no {@code Environment}
	 */
	ArrayList<Target> targetWithNoEnvironment;
	
	/**
	 * A {@code String} variable that is use for selection of rule effect
	 */
	String appliedEffect;
	
	/**
	 * An {@code ArrayList} of {@code String} that has all rule effects
	 */
	List<String> ruleEffects = new ArrayList<String>();
	
	/************************************************** Getter Methods *****************************************/

	/**
	 * Returns the value of {@code subjListTarg} property
	 * 
	 * @return subjListTarg
	 */
	public List<Object[]> getSubjListTarg() {
		log.debug("Get  subjListTarg: " + subjListTarg);
		return subjListTarg;
	}

	/**
	 * Returns the value of {@code resListTarg} property
	 * 
	 * @return resListTarg
	 */
	public List<Object[]> getResListTarg() {
		log.debug("Get  resListTarg: " + resListTarg);
		return resListTarg;
	}

	/**
	 * Returns the value of {@code ActListTarg} property
	 * 
	 * @return actListTarg
	 */
	public List<Object[]> getActListTarg() {
		log.debug("Get  actListTarg: " + actListTarg);
		return actListTarg;
	}

	/**
	 * Returns the value of {@code EnvListTarg} property
	 * 
	 * @return envListTarg
	 */
	public List<Object[]> getEnvListTarg() {
		log.debug("Get  envListTarg: " + envListTarg);
		return envListTarg;
	}
	
	/**
	 * Returns the value of {@code reqInterval} property
	 * 
	 * @return reqInterval
	 */
	public String getReqInterval() {
		log.debug("Get  reqInterval: " + reqInterval);
		return reqInterval;
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
	 * Returns the value of {@code selectedSubAttrValues} property
	 * 
	 * @return selectedSubAttrValues
	 */
	public ArrayList<SubAttrValues> getSelectedSubAttrValues() {
		log.debug("Get  selectedSubAttrValues: " + selectedSubAttrValues);
		return selectedSubAttrValues;
	}
	
	/**
	 * Returns the value of {@code selectedSubMatchIds} property
	 * 
	 * @return selectedSubMatchIds
	 */
	public ArrayList<String> getSelectedSubMatchIds() {
		log.debug("Get  selectedSubMatchIds: " + selectedSubMatchIds);
		return selectedSubMatchIds;
	}
	
	/**
	 * Returns the value of {@code selectedResAttrValues} property
	 * 
	 * @return selectedResAttrValues
	 */
	public ArrayList<ResAttrValues> getSelectedResAttrValues() {
		log.debug("Get  selectedResAttrValues: " + selectedResAttrValues);
		return selectedResAttrValues;
	}
	/**
	 * Returns the value of {@code selectedResMatchIds} property
	 * 
	 * @return selectedResMatchIds
	 */
	public ArrayList<String> getSelectedResMatchIds() {
		log.debug("Get  selectedResMatchIds: " + selectedResMatchIds);
		return selectedResMatchIds;
	}
	/**
	 * Returns the value of {@code selectedActAttrValues} property
	 * 
	 * @return selectedActAttrValues
	 */
	public ArrayList<ActAttrValues> getSelectedActAttrValues() {
		log.debug("Get  selectedActAttrValues: " + selectedActAttrValues);
		return selectedActAttrValues;
	}
	/**
	 * Returns the value of {@code selectedActMatchIds} property
	 * 
	 * @return selectedActMatchIds
	 */
	public ArrayList<String> getSelectedActMatchIds() {
		log.debug("Get  selectedActMatchIds: " + selectedActMatchIds);
		return selectedActMatchIds;
	}
	/**
	 * Returns the value of {@code selectedEnvAttrValues} property
	 * 
	 * @return selectedEnvAttrValues
	 */
	public ArrayList<EnvAttrValues> getSelectedEnvAttrValues() {
		log.debug("Get  selectedEnvAttrValues: " + selectedEnvAttrValues);
		return selectedEnvAttrValues;
	}
	/**
	 * Returns the value of {@code selectedEnvMatchIds} property
	 * 
	 * @return selectedEnvMatchIds
	 */
	public ArrayList<String> getSelectedEnvMatchIds() {
		log.debug("Get  selectedEnvMatchIds: " + selectedEnvMatchIds);
		return selectedEnvMatchIds;
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
	 * Returns the value of {@code policyDao} property
	 * 
	 * @return policyDao
	 */
	public PolicyDAO getPolicyDao() {
		log.debug("Get  policyDao: " + policyDao);
		return policyDao;
	}

	
	/**
	 * Returns the value of {@code onGoingTimes} property
	 * 
	 * @return onGoingTimes
	 */
	public List<String> getOnGoingTimes() {
		log.debug("Get  onGoingTimes: " + onGoingTimes);
		return onGoingTimes;
	}
	
	
	/**
	 * Returns the value of {@code number} property
	 * 
	 * @return number
	 */
	public ArrayList<String> getNumber() {
		log.debug("Get  number: " + number);
		return number;
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
	 * Returns the value of {@code functionOneArg} property
	 * 
	 * @return functionOneArg
	 */
	public List<String> getFunctionOneArg() {
		log.debug("Get  functionOneArg: " + functionOneArg);
		return functionOneArg;
	}
	
	
	/**
	 * Returns the value of {@code daoSubject} property
	 * 
	 * @return daoSubject
	 */
	public SubjectDAO getDaoSubject() {
		log.debug("Get  daoSubject: " + daoSubject);
		return daoSubject;
	}
	/**
	 * Returns the value of {@code daoSubjectAttribute} property
	 * 
	 * @return daoSubjectAttribute
	 */
	public SubjectAttributeDAO getDaoSubjectAttribute() {
		log.debug("Get  daoSubjectAttribute: " + daoSubjectAttribute);
		return daoSubjectAttribute;
	}
	/**
	 * Returns the value of {@code daoSubjectAttributeValue} property
	 * 
	 * @return daoSubjectAttributeValue
	 */
	public SubAttrValuesDAO getDaoSubjectAttributeValue() {
		log.debug("Get  daoSubjectAttributeValue: " + daoSubjectAttributeValue);
		return daoSubjectAttributeValue;
	}
	/**
	 * Returns the value of {@code daoRes} property
	 * 
	 * @return daoRes
	 */
	public ResourceDAO getDaoRes() {
		log.debug("Get  daoRes: " + daoRes);
		return daoRes;
	}
	/**
	 * Returns the value of {@code daoResourceAttribute} property
	 * 
	 * @return daoResourceAttribute
	 */
	public ResourceAttributeDAO getDaoResourceAttribute() {
		log.debug("Get  daoResourceAttribute: " + daoResourceAttribute);
		return daoResourceAttribute;
	}
	/**
	 * Returns the value of {@code daoResourceAttributeValue} property
	 * 
	 * @return daoResourceAttributeValue
	 */
	public ResAttrValuesDAO getDaoResourceAttributeValue() {
		log.debug("Get  daoResourceAttributeValue: " + daoResourceAttributeValue);
		return daoResourceAttributeValue;
	}
	/**
	 * Returns the value of {@code daoAction} property
	 * 
	 * @return daoAction
	 */
	public ActionDAO getDaoAction() {
		log.debug("Get  daoAction: " + daoAction);
		return daoAction;
	}
	/**
	 * Returns the value of {@code daoActionAttribute} property
	 * 
	 * @return daoActionAttribute
	 */
	public ActionAttributeDAO getDaoActionAttribute() {
		log.debug("Get  daoActionAttribute: " + daoActionAttribute);
		return daoActionAttribute;
	}
	/**
	 * Returns the value of {@code daoActionAttributeValue} property
	 * 
	 * @return daoActionAttributeValue
	 */
	public ActAttrValuesDAO getDaoActionAttributeValue() {
		log.debug("Get  daoActionAttributeValue: " + daoActionAttributeValue);
		return daoActionAttributeValue;
	}
	/**
	 * Returns the value of {@code daoEnv} property
	 * 
	 * @return daoEnv
	 */
	public EnvironmentDAO getDaoEnv() {
		log.debug("Get  daoEnv: " + daoEnv);
		return daoEnv;
	}
	/**
	 * Returns the value of {@code envattrdao} property
	 * 
	 * @return envattrdao
	 */
	public EnvironmentAttributeDAO getEnvattrdao() {
		log.debug("Get  envattrdao: " + envattrdao);
		return envattrdao;
	}
	/**
	 * Returns the value of {@code envattrvaluesdao} property
	 * 
	 * @return envattrvaluesdao
	 */
	public EnvAttrValuesDAO getEnvattrvaluesdao() {
		log.debug("Get  envattrvaluesdao: " + envattrvaluesdao);
		return envattrvaluesdao;
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
	 * Returns the value of {@code createdApply} property
	 * 
	 * @return createdApply
	 */
	public ArrayList<Apply> getCreatedApply() {
		log.debug("Get  createdApply: " + createdApply);
		return createdApply;
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
	 * Returns the value of {@code opertionFail} property
	 * 
	 * @return opertionFail
	 */
	public boolean isOpertionFail() {
		log.debug("Get  opertionFail: " + opertionFail);
		return opertionFail;
	}

	

	/**
	 * Returns the value of {@code addbtn} property
	 * 
	 * @return addbtn
	 */
	public boolean isAddbtn() {
		log.debug("Get  addbtn: " + addbtn);
		return addbtn;
	}

	
	
	
	/**
	 * Returns the value of {@code allTargSubjects} property
	 * 
	 * @return allTargSubjects
	 */
	public ArrayList<Subjects> getAllTargSubjects() {
		
		if (clickedTarget != null) {
			ArrayList<Subjects> targetSubs = (ArrayList<Subjects>) dao
					.populateTargetSubjects(clickedTarget.getPkTarget());
			int i = 0;
			for (Subjects s : targetSubs) {
				System.out.println("Subjects : -> " + i + " " + s);
				i++;
			}
			log.debug("Get  allTargSubjects: " + targetSubs);
			return targetSubs;
		}
		log.debug("Get  allTargSubjects: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code allTargResources} property
	 * 
	 * @return allTargResources
	 */
	public ArrayList<Resources> getAllTargResources() {
		if (clickedTarget != null){
			log.debug("Get  allTargResources: " + (ArrayList<Resources>) dao
					.populateTargetSubjectsResources(clickedTarget
							.getPkTarget()));
			return (ArrayList<Resources>) dao
					.populateTargetSubjectsResources(clickedTarget
							.getPkTarget());
		}
		log.debug("Get  allTargResources: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code allTargActions} property
	 * 
	 * @return allTargActions
	 */
	public ArrayList<Actions> getAllTargActions() {
		if (clickedTarget != null){
			log.debug("Get  allTargActions: " + (ArrayList<Actions>) dao.populateTargetActions(clickedTarget
					.getPkTarget()));
			return (ArrayList<Actions>) dao.populateTargetActions(clickedTarget
					.getPkTarget());
		}
		log.debug("Get  allTargActions: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code allTargEnvironments} property
	 * 
	 * @return allTargEnvironments
	 */
	public ArrayList<Environments> getAllTargEnvironments() {

		if (clickedConditionTarget != null) {
			log.debug("Get  allTargEnvironments: " + (ArrayList<Environments>) dao
					.populateTargetEnvironments(clickedConditionTarget
							.getPkTarget()));
			return (ArrayList<Environments>) dao
					.populateTargetEnvironments(clickedConditionTarget
							.getPkTarget());
		}
		log.debug("Get  allTargEnvironments: " + null);
		return null;
	}

	
	
	
	/**
	 * Returns the value of {@code allTarget} property
	 * 
	 * @return allTarget
	 */
	public ArrayList<Target> getAllTarget() {
		ArrayList<Target> targets = (ArrayList<Target>) dao.selectTarget();
		log.debug("Get  allTarget: " + targets);
		return targets;
	}

	

	/**
	 * Returns the value of {@code clickedTarget} property
	 * 
	 * @return clickedTarget
	 */
	public Target getClickedTarget() {
		log.debug("Get  clickedTarget: " + clickedTarget);
		return clickedTarget;
	}
	
	
	
	
	

	
	/**
	 * Returns the value of {@code selectedSubValue} property
	 * 
	 * @return selectedSubValue
	 */
	public SubAttrValues getSelectedSubValue() {
		log.debug("Get  selectedSubValue: " + selectedSubValue);
		return selectedSubValue;
	}

	

	/**
	 * Returns the value of {@code selectedActValue} property
	 * 
	 * @return selectedActValue
	 */
	public ActAttrValues getSelectedActValue() {
		log.debug("Get  selectedActValue: " + selectedActValue);
		return selectedActValue;
	}

	

	/**
	 * Returns the value of {@code selectedResValue} property
	 * 
	 * @return selectedResValue
	 */
	public ResAttrValues getSelectedResValue() {
		log.debug("Get  selectedResValue: " + selectedResValue);
		return selectedResValue;
	}

	

	/**
	 * Returns the value of {@code selectedEnvValue} property
	 * 
	 * @return selectedEnvValue
	 */
	public EnvAttrValues getSelectedEnvValue() {
		log.debug("Get  selectedEnvValue: " + selectedEnvValue);
		return selectedEnvValue;
	}

	

	/**
	 * Returns the value of {@code selectedAction} property
	 * 
	 * @return selectedAction
	 */
	public Action getSelectedAction() {
		log.debug("Get  selectedAction: " + selectedAction);
		return selectedAction;
	}

	
	/**
	 * Returns the value of {@code selectedActionAttributes} property
	 * 
	 * @return selectedActionAttributes
	 */
	public ActionAttribute getSelectedActionAttributes() {
		log.debug("Get  selectedActionAttributes: " + selectedActionAttributes);
		return selectedActionAttributes;
	}

	

	/**
	 * Returns the value of {@code description} property
	 * 
	 * @return description
	 */
	public String getDescription() {
		if (clickedTarget != null)
			this.description = clickedTarget.getDescription();
		log.debug("Get  description: " + description);
		return description;
	}

	
	/**
	 * Returns the value of {@code selectedSubAttValue} property
	 * 
	 * @return selectedSubAttValue
	 */
	public String getSelectedSubAttValue() {
		log.debug("Get  selectedSubAttValue: " + selectedSubAttValue);
		return selectedSubAttValue;
	}

	
	/**
	 * Returns the value of {@code allResAttributes} property
	 * 
	 * @return allResAttributes
	 */
	public ArrayList<ResourceAttribute> getAllResAttributes() {
		if (selectedResource != null){
			log.debug("Get  allResAttributes: " + (ArrayList<ResourceAttribute>) daoResourceAttribute
					.selectResourceAttributes(selectedResource.getPkResource()));
			return (ArrayList<ResourceAttribute>) daoResourceAttribute
					.selectResourceAttributes(selectedResource.getPkResource());	
		}
		// return allAttributes;
		else{
			log.debug("Get  allResAttributes: " + null);
			return null;
		}

	}

	

	/**
	 * Returns the value of {@code targetActions} property
	 * 
	 * @return targetActions
	 */
	public ArrayList<Action> getTargetActions() {
		log.debug("Get  targetActions: " + (ArrayList<Action>) daoAction.selectAction());
		return (ArrayList<Action>) daoAction.selectAction();
	}

	/**
	 * Returns the value of {@code targetResources} property
	 * 
	 * @return targetResources
	 */
	public ArrayList<Resource> getTargetResources() {
		log.debug("Get  targetResources: " + (ArrayList<Resource>) daoRes.selectResource());
		return (ArrayList<Resource>) daoRes.selectResource();
	}
	
	/**
	 * Returns the value of {@code targetSubjects} property
	 * 
	 * @return targetSubjects
	 */
	public ArrayList<Subject> getTargetSubjects() {
		log.debug("Get  targetSubjects: " + (ArrayList<Subject>) daoSubject.selectSubject());
		return (ArrayList<Subject>) daoSubject.selectSubject();
	}

	

	/**
	 * Returns the value of {@code matchIds} property
	 * 
	 * @return matchIds
	 */
	public ArrayList<String> getMatchIds() {
		log.debug("Get  matchIds: " + matchIds);
		return this.matchIds;
	}

	

	

	/**
	 * Returns the value of {@code targetEnvironments} property
	 * 
	 * @return targetEnvironments
	 */
	public ArrayList<Environment> getTargetEnvironments() {
		log.debug("Get  targetEnvironments: " + (ArrayList<Environment>) daoEnv.selectEnvironment());
		return (ArrayList<Environment>) daoEnv.selectEnvironment();
	}

	
	/**
	 * Returns the value of {@code dao} property
	 * 
	 * @return dao
	 */
	public TargetDAO getDao() {
		log.debug("Get  dao: " + dao);
		return dao;
	}

	

	/**
	 * Returns the value of {@code selectedSubject} property
	 * 
	 * @return selectedSubject
	 */
	public Subject getSelectedSubject() {
		log.debug("Get  selectedSubject: " + selectedSubject);
		return selectedSubject;

	}

	
	/**
	 * Returns the value of {@code selectedResource} property
	 * 
	 * @return selectedResource
	 */
	public Resource getSelectedResource() {
		log.debug("Get  selectedResource: " + selectedResource);
		return selectedResource;

	}

	/**
	 * Returns the value of {@code allSubAttributes} property
	 * 
	 * @return allSubAttributes
	 */
	public ArrayList<SubjectAttribute> getAllSubAttributes() {
		if (selectedSubject != null){
			log.debug("Get  allSubAttributes: " + (ArrayList<SubjectAttribute>) daoSubjectAttribute
					.selectSubjectAttributes(selectedSubject.getPkSubject()));
			return (ArrayList<SubjectAttribute>) daoSubjectAttribute
					.selectSubjectAttributes(selectedSubject.getPkSubject());
		}
		else{
			log.debug("Get  allSubAttributes: " + null);
			return null;
		}

	}

	

	/**
	 * Returns the value of {@code allSubValues} property
	 * 
	 * @return allSubValues
	 */
	public ArrayList<SubAttrValues> getAllSubValues() {
		if (selectedSubjectAttributes != null){
			log.debug("Get  allSubValues: " + (ArrayList<SubAttrValues>) daoSubjectAttributeValue
					.populateSubValueList(selectedSubjectAttributes
							.getPkSubAttr()));
			return (ArrayList<SubAttrValues>) daoSubjectAttributeValue
					.populateSubValueList(selectedSubjectAttributes
							.getPkSubAttr());
		}
		log.debug("Get  allSubValues: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code allResValues} property
	 * 
	 * @return allResValues
	 */
	public ArrayList<ResAttrValues> getAllResValues() {
		if (selectedResourceAttribute != null){
			log.debug("Get  allResValues: " + (ArrayList<ResAttrValues>) daoResourceAttributeValue
					.populateResValueList(selectedResourceAttribute
							.getPkResAttr()));
			return (ArrayList<ResAttrValues>) daoResourceAttributeValue
					.populateResValueList(selectedResourceAttribute
							.getPkResAttr());	
		}
		// return allValues;
		log.debug("Get  allResValues: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code selectedSubjectAttributes} property
	 * 
	 * @return selectedSubjectAttributes
	 */
	public SubjectAttribute getSelectedSubjectAttributes() {
		log.debug("Get  selectedSubjectAttributes: " + selectedSubjectAttributes);
		return selectedSubjectAttributes;
	}
	/**
	 * Returns the value of {@code selectedResourceAttribute} property
	 * 
	 * @return selectedResourceAttribute
	 */
	public ResourceAttribute getSelectedResourceAttribute() {
		log.debug("Get  selectedResourceAttribute: " + selectedResourceAttribute);
		return selectedResourceAttribute;
	}

	

	/**
	 * Returns the value of {@code allActAttributes} property
	 * 
	 * @return allActAttributes
	 */
	public ArrayList<ActionAttribute> getAllActAttributes() {
		if (selectedAction != null){
			log.debug("Get  allActAttributes: " + (ArrayList<ActionAttribute>) daoActionAttribute
					.selectActionAttributes(selectedAction.getPkAction()));
			return (ArrayList<ActionAttribute>) daoActionAttribute
					.selectActionAttributes(selectedAction.getPkAction());
		}
		log.debug("Get  allActAttributes: " + null);
		return null;

	}

	/**
	 * Returns the value of {@code allActValues} property
	 * 
	 * @return allActValues
	 */
	public ArrayList<ActAttrValues> getAllActValues() {
		if (selectedActionAttributes != null){
			log.debug("Get  allActValues: " + (ArrayList<ActAttrValues>) daoActionAttributeValue
					.populateActValueList(selectedActionAttributes
							.getPkActAttr()));
			return (ArrayList<ActAttrValues>) daoActionAttributeValue
					.populateActValueList(selectedActionAttributes
							.getPkActAttr());
		}
		log.debug("Get  allActValues: " + null);
		return null;
	}

	

	/**
	 * Returns the value of {@code selectedEnvironment} property
	 * 
	 * @return selectedEnvironment
	 */
	public Environment getSelectedEnvironment() {
		log.debug("Get  selectedEnvironment: " + selectedEnvironment);
		return selectedEnvironment;
	}

	
	/**
	 * Returns the value of {@code selectedEnvironmentAttribute} property
	 * 
	 * @return selectedEnvironmentAttribute
	 */
	public EnvironmentAttribute getSelectedEnvironmentAttribute() {
		log.debug("Get  selectedEnvironmentAttribute: " + selectedEnvironmentAttribute);
		return selectedEnvironmentAttribute;
	}

	
	/**
	 * Returns the value of {@code allEnvAttribute} property
	 * 
	 * @return allEnvAttribute
	 */
	public ArrayList<EnvironmentAttribute> getAllEnvAttributes() {
		if (selectedEnvironment != null){
			log.debug("Get  allEnvAttribute: " + (ArrayList<EnvironmentAttribute>) envattrdao
					.selectEnvironmentAttributes(selectedEnvironment
							.getPkEnvironment()));
			return (ArrayList<EnvironmentAttribute>) envattrdao
					.selectEnvironmentAttributes(selectedEnvironment
							.getPkEnvironment());
		}
		log.debug("Get  allEnvAttribute: " + null);
		return null;

	}
	
	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	

	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public ArrayList<EnvAttrValues> getAllEnvValues() {
		if (selectedEnvironmentAttribute != null){
			log.debug("Get  applyType: " + applyType);
			return (ArrayList<EnvAttrValues>) envattrvaluesdao
					.selectEnvAttrValue(selectedEnvironmentAttribute
							.getPkEnvAttr());
		}
		log.debug("Get  applyType: " + applyType);
		return null;

	}

	
	
	
	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public String getSelectedMatchId() {
		log.debug("Get  applyType: " + applyType);
		return selectedMatchId;
	}

	
	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public String getUpdatedDescription() {
		if (clickedTarget != null)
			this.updatedDescription = clickedTarget.getDescription();
		log.debug("Get  applyType: " + applyType);
		return updatedDescription;
	}

	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public String getUpdatedTargetId() {
		if (clickedTarget != null)
			this.updatedTargetId = clickedTarget.getTargetId();
		log.debug("Get  applyType: " + applyType);
		return updatedTargetId;
	}
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public Subjects getSelectedSubjects() {
		log.debug("Get  applyType: " + applyType);
		return selectedSubjects;
	}
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public Resources getSelectedResources() {
		log.debug("Get  applyType: " + applyType);
		return selectedResources;
	}
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public Actions getSelectedActions() {
		log.debug("Get  applyType: " + applyType);
		return selectedActions;
	}

	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public Environments getSelectedEnvironments() {
		log.debug("Get  applyType: " + applyType);
		return selectedEnvironments;
	}

	
	
	
	
	
	
	
	/**
	 * Returns the value of {@code addedTargetSubject} property
	 * 
	 * @return addedTargetSubject
	 */
	public Subject getAddedTargetSubject() {
		log.debug("Get  addedTargetSubject: " + addedTargetSubject);
		return addedTargetSubject;
	}

	
	/**
	 * Returns the value of {@code addedTargetResource} property
	 * 
	 * @return addedTargetResource
	 */
	public Resource getAddedTargetResource() {
		log.debug("Get  addedTargetResource: " + addedTargetResource);
		return addedTargetResource;
	}

	
	/**
	 * Returns the value of {@code addedTargetAction} property
	 * 
	 * @return addedTargetAction
	 */
	public Action getAddedTargetAction() {
		log.debug("Get  addedTargetAction: " + addedTargetAction);
		return addedTargetAction;
	}

	
	/**
	 * Returns the value of {@code addedTargetEnvironment} property
	 * 
	 * @return addedTargetEnvironment
	 */
	public Environment getAddedTargetEnvironment() {
		log.debug("Get  addedTargetEnvironment: " + addedTargetEnvironment);
		return addedTargetEnvironment;
	}

	
	
	

	
	
	/**
	 * Returns the value of {@code matchIdAndValueS} property
	 * 
	 * @return matchIdAndValueS
	 */
	public String getMatchIdAndValueS(Subjects s) {
		log.debug("Get  matchIdAndValueS: " + dao.getMatchIdAndValue(s));
		return dao.getMatchIdAndValue(s);
	}
	/**
	 * Returns the value of {@code matchIdAndValueR} property
	 * 
	 * @return matchIdAndValueR
	 */
	public String getMatchIdAndValueR(Resources r) {
		log.debug("Get  matchIdAndValueR: " + dao.getMatchIdAndValue(r));
		return dao.getMatchIdAndValue(r);
	}
	/**
	 * Returns the value of {@code matchIdAndValueA} property
	 * 
	 * @return matchIdAndValueA
	 */
	public String getMatchIdAndValueA(Actions a) {
		log.debug("Get  matchIdAndValueA: " + dao.getMatchIdAndValue(a));
		return dao.getMatchIdAndValue(a);
	}
	/**
	 * Returns the value of {@code matchIdAndValueE} property
	 * 
	 * @return matchIdAndValueE
	 */
	public String getMatchIdAndValueE(Environments e) {
		log.debug("Get  matchIdAndValueE: " + dao.getMatchIdAndValue(e));
		return dao.getMatchIdAndValue(e);
	}
	/**
	 * Returns the value of {@code splittedMatchId} property
	 * 
	 * @return splittedMatchId
	 */
	public String getSplittedMatchId(String matchID) {
		String[] splittedMatchIds = matchID.split(":");
		log.debug("Get  splittedMatchId: " + splittedMatchIds[7]);
		return splittedMatchIds[7];
	}
	/**
	 * Returns the value of {@code mustBePresent} property
	 * 
	 * @return mustBePresent
	 */
	public boolean isMustBePresent() {
		log.debug("Get  mustBePresent: " + mustBePresent);
		return mustBePresent;
	}

	
	/**
	 * Returns the value of {@code policyName} property
	 * 
	 * @return policyName
	 */
	public String getPolicyName() {
		log.debug("Get  policyName: " + policyName);
		return policyName;
	}

	
	/**
	 * Returns the value of {@code algorithmList} property
	 * 
	 * @return algorithmList
	 */
	public List<String> getAlgorithmList() {
		log.debug("Get  algorithmList: " + algorithmList);
		return algorithmList;
	}

	
	/**
	 * Returns the value of {@code policyDescription} property
	 * 
	 * @return policyDescription
	 */
	public String getPolicyDescription() {
		log.debug("Get  policyDescription: " + policyDescription);
		return policyDescription;
	}

	
	/**
	 * Returns the value of {@code appliedAlgo} property
	 * 
	 * @return appliedAlgo
	 */
	public String getAppliedAlgo() {
		log.debug("Get  appliedAlgo: " + appliedAlgo);
		return appliedAlgo;
	}

	
	/**
	 * Returns the value of {@code onGoingTime} property
	 * 
	 * @return onGoingTime
	 */
	public String getOnGoingTime() {
		log.debug("Get  onGoingTime: " + onGoingTime);
		return onGoingTime;
	}

	

	/**
	 * Returns the value of {@code attrIds} property
	 * 
	 * @return attrIds
	 */
	public List<String> getAttrIds() {
		if (attrIds.isEmpty()) {
			SubjectDAO allSubjects = new SubjectDAO();
			ArrayList<Subject> subjects = (ArrayList<Subject>) allSubjects
					.selectSubject();
			Iterator<Subject> iter = subjects.iterator();
			while (iter.hasNext()) {
				SubjectAttributeDAO daoSubjectAttribute = new SubjectAttributeDAO();
				ArrayList<SubjectAttribute> sa = (ArrayList<SubjectAttribute>) daoSubjectAttribute
						.selectSubjectAttributes(((Subject) iter.next())
								.getPkSubject());
				Iterator<SubjectAttribute> iterSa = sa.iterator();
				while (iterSa.hasNext()) {
					SubjectAttribute s = (SubjectAttribute) iterSa.next();
					String tempSubAttrId = s.getSubjAttrId();
					Iterator<String> tempIt = this.attrIds.iterator();
					int index = 0;
					while (tempIt.hasNext()) {
						String subAttrIdInList = tempIt.next();
						if (subAttrIdInList.equals(tempSubAttrId))
							break;
						index++;
					}
					if (index == this.attrIds.size())
						this.attrIds.add(s.getSubjAttrId());
				}
			}

			ResourceDAO allResources = new ResourceDAO();
			ArrayList<Resource> resources = (ArrayList<Resource>) allResources
					.selectResource();
			Iterator<Resource> iterR = resources.iterator();
			while (iterR.hasNext()) {
				ResourceAttributeDAO daoResourceAttribute = new ResourceAttributeDAO();
				ArrayList<ResourceAttribute> re = (ArrayList<ResourceAttribute>) daoResourceAttribute
						.selectResourceAttributes(((Resource) iterR.next())
								.getPkResource());
				Iterator<ResourceAttribute> iterRe = re.iterator();
				while (iterRe.hasNext()) {
					ResourceAttribute r = (ResourceAttribute) iterRe.next();
					String tempResAttrId = r.getResAttrId();
					Iterator<String> tempIt = this.attrIds.iterator();
					int index = 0;
					while (tempIt.hasNext()) {
						String resAttrIdInList = tempIt.next();
						if (resAttrIdInList.equals(tempResAttrId))
							break;
						index++;
					}
					if (index == this.attrIds.size())
						this.attrIds.add(r.getResAttrId());
				}
			}

			ActionDAO allActions = new ActionDAO();
			ArrayList<Action> actions = (ArrayList<Action>) allActions
					.selectAction();
			Iterator<Action> iterA = actions.iterator();
			while (iterA.hasNext()) {
				ActionAttributeDAO daoActionAttribute = new ActionAttributeDAO();
				ArrayList<ActionAttribute> ac = (ArrayList<ActionAttribute>) daoActionAttribute
						.selectActionAttributes(((Action) iterA.next())
								.getPkAction());
				Iterator<ActionAttribute> iterAc = ac.iterator();
				while (iterAc.hasNext()) {
					ActionAttribute a = (ActionAttribute) iterAc.next();
					String tempActAttrId = a.getActAttrId();
					Iterator<String> tempIt = this.attrIds.iterator();
					int index = 0;
					while (tempIt.hasNext()) {
						String actAttrIdInList = tempIt.next();
						if (actAttrIdInList.equals(tempActAttrId))
							break;
						index++;
					}
					if (index == this.attrIds.size())
						this.attrIds.add(a.getActAttrId());
				}
			}

			EnvironmentDAO allEnvironments = new EnvironmentDAO();
			ArrayList<Environment> environments = (ArrayList<Environment>) allEnvironments
					.selectEnvironment();
			// System.out.println("Junaid Env Size is "+environments.size());
			Iterator<Environment> iterE = environments.iterator();
			while (iterE.hasNext()) {
				EnvironmentAttributeDAO envattrdao = new EnvironmentAttributeDAO();
				ArrayList<EnvironmentAttribute> en = (ArrayList<EnvironmentAttribute>) envattrdao
						.selectEnvironmentAttributes(((Environment) iterE
								.next()).getPkEnvironment());
				Iterator<EnvironmentAttribute> iterEn = en.iterator();
				while (iterEn.hasNext()) {
					EnvironmentAttribute e = (EnvironmentAttribute) iterEn
							.next();
					String tempEnvAttrId = e.getEnvAttrId();
					Iterator<String> tempIt = this.attrIds.iterator();
					int index = 0;
					while (tempIt.hasNext()) {
						String envAttrIdInList = tempIt.next();
						if (envAttrIdInList.equals(tempEnvAttrId))
							break;
						index++;
					}
					if (index == this.attrIds.size()) {
						System.out.println("->" + e.getEnvAttrId());
						this.attrIds.add(e.getEnvAttrId());
					}

				}
			}

		}
		log.debug("Get  attrIds: " + attrIds);
		return this.attrIds;
	}
	
	
	

	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public List<String> getonGoingAttrIds() {
		log.debug("Get  onGoingAttrIds: " + onGoingAttrIds);
		return onGoingAttrIds;
	}

	
	/**
	 * Returns the value of {@code postAttrIds} property
	 * 
	 * @return postAttrIds
	 */
	public List<String> getPostAttrIds() {
		log.debug("Get  postAttrIds: " + postAttrIds);
		return postAttrIds;
	}

	
	/**
	 * Returns the value of {@code selectedPreUpdate} property
	 * 
	 * @return selectedPreUpdate
	 */
	public AttributeAssignment getSelectedPreUpdate() {
		log.debug("Get  selectedPreUpdate: " + selectedPreUpdate);
		return selectedPreUpdate;
	}

	
	/**
	 * Returns the value of {@code selectedOnGoingUpdate} property
	 * 
	 * @return selectedOnGoingUpdate
	 */
	public AttributeAssignment getSelectedOnGoingUpdate() {
		log.debug("Get  selectedOnGoingUpdate: " + selectedOnGoingUpdate);
		return selectedOnGoingUpdate;
	}

	
	/**
	 * Returns the value of {@code selectedPostUpdate} property
	 * 
	 * @return selectedPostUpdate
	 */
	public AttributeAssignment getSelectedPostUpdate() {
		log.debug("Get  selectedPostUpdate: " + selectedPostUpdate);
		return selectedPostUpdate;
	}

	
	/**
	 * Returns the value of {@code preUpdateCheckBox} property
	 * 
	 * @return preUpdateCheckBox
	 */
	public boolean isPreUpdateCheckBox() {
		log.debug("Get  preUpdateCheckBox: " + preUpdateCheckBox);
		return preUpdateCheckBox;
	}

	
	/**
	 * Returns the value of {@code onGoingUpdateCheckBox} property
	 * 
	 * @return onGoingUpdateCheckBox
	 */
	public boolean isOnGoingUpdateCheckBox() {
		log.debug("Get  onGoingUpdateCheckBox: " + onGoingUpdateCheckBox);
		return this.onGoingUpdateCheckBox;
	}

	
	/**
	 * Returns the value of {@code postUpdateCheckBox} property
	 * 
	 * @return postUpdateCheckBox
	 */
	public boolean isPostUpdateCheckBox() {
		log.debug("Get  postUpdateCheckBox: " + postUpdateCheckBox);
		return postUpdateCheckBox;
	}

	
	/**
	 * Returns the value of {@code preAttrId} property
	 * 
	 * @return preAttrId
	 */
	public String getPreAttrId() {
		log.debug("Get  preAttrId: " + preAttrId);
		return preAttrId;
	}

	
	/**
	 * Returns the value of {@code preValue} property
	 * 
	 * @return preValue
	 */
	public String getPreValue() {
		log.debug("Get  preValue: " + preValue);
		return preValue;
	}

	
	/**
	 * Returns the value of {@code preValues} property
	 * 
	 * @return preValues
	 */
	public List<AttributeAssignment> getPreValues() {
		log.debug("Get  preValues: " + preValues);
		return preValues;
	}

	
	/**
	 * Returns the value of {@code onGoingAttrId} property
	 * 
	 * @return onGoingAttrId
	 */
	public String getOnGoingAttrId() {
		log.debug("Get  onGoingAttrId: " + onGoingAttrId);
		return onGoingAttrId;
	}

	
	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return onGoingValue
	 */
	public String getOnGoingValue() {
		log.debug("Get  onGoingValue: " + onGoingValue);
		return onGoingValue;
	}

	
	/**
	 * Returns the value of {@code onGoingValues} property
	 * 
	 * @return onGoingValues
	 */
	public List<AttributeAssignment> getOnGoingValues() {
		log.debug("Get  onGoingValues: " + onGoingValues);
		return onGoingValues;
	}

	
	/**
	 * Returns the value of {@code postAttrId} property
	 * 
	 * @return postAttrId
	 */
	public String getPostAttrId() {
		log.debug("Get  postAttrId: " + postAttrId);
		return postAttrId;
	}

	
	/**
	 * Returns the value of {@code postValue} property
	 * 
	 * @return postValue
	 */
	public String getPostValue() {
		log.debug("Get  postValue: " + postValue);
		return postValue;
	}

	
	/**
	 * Returns the value of {@code postValues} property
	 * 
	 * @return postValues
	 */
	public List<AttributeAssignment> getPostValues() {
		log.debug("Get  postValues: " + postValues);
		return postValues;
	}

	
	/**
	 * Returns the value of {@code dataTypes} property
	 * 
	 * @return dataTypes
	 */
	public List<String> getDataTypes() {
		log.debug("Get  dataTypes: " + dataTypes);
		return dataTypes;
	}

	
	
	
	
	
	
	/**
	 * Returns the value of {@code pre} property
	 * 
	 * @return pre
	 */
	public boolean isPre() {
		log.debug("Get  pre: " + pre);
		return pre;
	}

	
	/**
	 * Returns the value of {@code on} property
	 * 
	 * @return on
	 */
	public boolean isOn() {
		log.debug("Get  on: " + on);
		return on;
	}

	
	/**
	 * Returns the value of {@code onGoingReqOrUpdate} property
	 * 
	 * @return onGoingReqOrUpdate
	 */
	public boolean isOnGoingReqOrUpdate() {
		log.debug("Get  onGoingReqOrUpdate: " + onGoingReqOrUpdate);
		return onGoingReqOrUpdate;
	}

	
	
	
	
	/**
	 * Returns the value of {@code selectedCondition} property
	 * 
	 * @return selectedCondition
	 */
	public Condition getSelectedCondition() {
		log.debug("Get  selectedCondition: " + selectedCondition);
		return selectedCondition;
	}

	
	/**
	 * Returns the value of {@code conditionDao} property
	 * 
	 * @return conditionDao
	 */
	public ConditionDAO getConditionDao() {
		log.debug("Get  conditionDao: " + conditionDao);
		return conditionDao;
	}

	
	/**
	 * Returns the value of {@code allCondition} property
	 * 
	 * @return allCondition
	 */
	public ArrayList<Condition> getAllCondition() {
		allCondition = (ArrayList<Condition>) conditionDao.selectCondition();
		log.debug("Get  allCondition: " + allCondition);
		return allCondition;
	}

	
	

	/**
	 * Returns the value of {@code attributeValue} property
	 * 
	 * @return attributeValue
	 */
	public boolean isOperationFail() {
		log.debug("Get  operationFail: " + operationFail);
		return operationFail;
	}
	
	
	
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
	 * Returns the value of {@code designatorType} property
	 * 
	 * @return designatorType
	 */
	public String getDesignatorType() {
		log.debug("Get  designatorType: " + designatorType);
		return designatorType;
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
	 * Returns the value of {@code apply} property
	 * 
	 * @return apply
	 */
	public Apply getApply() {
		log.debug("Get  apply: " + apply);
		return apply;
	}

	
	/**
	 * Returns the value of {@code arguments} property
	 * 
	 * @return arguments
	 */
	public List<String> getArguments() {
		log.debug("Get  arguments: " + arguments);
		return arguments;
	}

	
	/**
	 * Returns the value of {@code functionID} property
	 * 
	 * @return functionID
	 */
	public List<String> getFunctionID() {
		log.debug("Get  functionID: " + functionID);
		return functionID;
	}

	
	/**
	 * Returns the value of {@code root} property
	 * 
	 * @return root
	 */
	public TreeNode getRoot() {
		log.debug("Get  root: " + root);
		root.setExpanded(true);
		return root;
	}

	
	/**
	 * Returns the value of {@code selectedNode} property
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
	 * Returns the value of {@code attributeDesignatorId} property
	 * 
	 * @return attributeDesignatorId
	 */
	public String getAttributeDesignatorId() {
		log.debug("Get  attributeDesignatorId: " + attributeDesignatorId);
		return attributeDesignatorId;
	}
	/**
	 * Returns the value of {@code selectedNumber} property
	 * 
	 * @return selectedNumber
	 */
	public String getSelectedNumber() {
		log.debug("Get  selectedNumber: " + selectedNumber);
		return selectedNumber;
	}

	
	
	
	/**
	 * Returns the value of {@code targetWithNoEnvironment} property
	 * 
	 * @return targetWithNoEnvironment
	 */
	public ArrayList<Target> getTargetWithNoEnvironment() {
		this.targetWithNoEnvironment = (ArrayList<Target>) this.dao
				.getTargetWithNoEnvironment();
		log.debug("Get  targetWithNoEnvironment: " + targetWithNoEnvironment);
		return targetWithNoEnvironment;
	}

	
	/**
	 * Returns the value of {@code preABC} property
	 * 
	 * @return preABC
	 */
	public String getPreABC() {
		log.debug("Get  preABC: " + preABC);
		return preABC;
	}

	
	/**
	 * Returns the value of {@code onGoingABC} property
	 * 
	 * @return onGoingABC
	 */
	public String getOnGoingABC() {
		log.debug("Get  onGoingABC: " + onGoingABC);
		return onGoingABC;
	}

	
	/**
	 * Returns the value of {@code clickedOblTarget} property
	 * 
	 * @return clickedOblTarget
	 */
	public Target getClickedOblTarget() {
		log.debug("Get  clickedOblTarget: " + clickedOblTarget);
		return clickedOblTarget;
	}

	
	/**
	 * Returns the value of {@code allOblTarget} property
	 * 
	 * @return allOblTarget
	 */
	public ArrayList<Target> getAllOblTarget() {
		this.allOblTarget = (ArrayList<Target>) dao.selectTarget();
		log.debug("Get  allOblTarget: " + allOblTarget);
		return allOblTarget;
	}

	
	/**
	 * Returns the value of {@code abcPropertiesCond} property
	 * 
	 * @return abcPropertiesCond
	 */
	public boolean isAbcPropertiesCond() {
		log.debug("Get  abcPropertiesCond: " + abcPropertiesCond);
		return abcPropertiesCond;
	}

	
	/**
	 * Returns the value of {@code allNotNullCondTargets} property
	 * 
	 * @return allNotNullCondTargets
	 */
	public ArrayList<Target> getAllNotNullCondTargets() {
		this.allNotNullCondTargets = (ArrayList<Target>) dao
				.getTargetWithEnvironment();
		log.debug("Get  allNotNullCondTargets: " + allNotNullCondTargets);
		return allNotNullCondTargets;
	}

	
	/**
	 * Returns the value of {@code clickedConditionTarget} property
	 * 
	 * @return clickedConditionTarget
	 */
	public Target getClickedConditionTarget() {
		log.debug("Get  clickedConditionTarget: " + clickedConditionTarget);
		return clickedConditionTarget;
	}

	
	/**
	 * Returns the value of {@code abcPropertiesObl} property
	 * 
	 * @return abcPropertiesObl
	 */
	public boolean isAbcPropertiesObl() {
		log.debug("Get  abcPropertiesObl: " + abcPropertiesObl);
		return abcPropertiesObl;
	}

	
	/**
	 * Returns the value of {@code abcPropertiesAuth} property
	 * 
	 * @return abcPropertiesAuth
	 */
	public boolean isAbcPropertiesAuth() {
		log.debug("Get  abcPropertiesAuth: " + abcPropertiesAuth);
		return abcPropertiesAuth;
	}

	
	/**
	 * Returns the value of {@code abcProperties} property
	 * 
	 * @return abcProperties
	 */
	public String getAbcProperties() {
		log.debug("Get  abcProperties: " + abcProperties);
		return abcProperties;
	}
	
	/**
	 * Returns the value of {@code propertyABC} property
	 * 
	 * @return propertyABC
	 */
	public String getPropertyABC() {
		log.debug("Get  propertyABC: " + propertyABC);
		return propertyABC;
	}
	
	/**
	 * Returns the value of {@code appliedEffect} property
	 * 
	 * @return appliedEffect
	 */
	public String getAppliedEffect() {
		log.debug("Get  appliedEffect: " + appliedEffect);
		return appliedEffect;
	}

	/**
	 * Returns the value of {@code ruleEffects} property
	 * 
	 * @return ruleEffects
	 */
	public List<String> getRuleEffects() {
		log.debug("Get  ruleEffects: " + ruleEffects);
		return ruleEffects;
	}
	
	
	/************************************************** Setter Methods *****************************************/
	
	/**
	 * Sets the {@code appliedEffect} property to {@code String} argument.
	 * 
	 * @param appliedEffect
	 */
	public void setAppliedEffect(String appliedEffect) {
		this.appliedEffect = appliedEffect;
		log.debug("Set  appliedEffect: " + appliedEffect);
	}

	/**
	 * Sets the {@code ruleEffects} property to {@code String} argument.
	 * 
	 * @param ruleEffects
	 */
	public void setRuleEffects(List<String> ruleEffects) {
		this.ruleEffects = ruleEffects;
		log.debug("Set  ruleEffects: " + ruleEffects);
	}

	/**
	 * Sets the {@code propertyABC} property to {@code String} argument.
	 * 
	 * @param propertyABC
	 */
	public void setPropertyABC(String propertyABC) {
		this.propertyABC = propertyABC;
		log.debug("Set  propertyABC: " + propertyABC);
	}

	/**
	 * Sets the {@code createdApply} property to {@code ArrayList<Apply>} argument.
	 * 
	 * @param createdApply
	 */
	public void setCreatedApply(ArrayList<Apply> createdApply) {
		this.createdApply = createdApply;
		log.debug("Set  createdApply: " + createdApply);
	}
	/**
	 * Sets the {@code allActAttributes} property to {@code ArrayList<ActionAttribute>} argument.
	 * 
	 * @param allActAttributes
	 */
	public void setAllActAttributes(ArrayList<ActionAttribute> allActAttributes) {
		this.allActAttributes = allActAttributes;
		log.debug("Set  allActAttributes: " + allActAttributes);
	}
	/**
	 * Sets the {@code reqInterval} property to {@code String} argument.
	 * 
	 * @param reqInterval
	 */
	public void setReqInterval(String reqInterval) {
		this.reqInterval = reqInterval;
		log.debug("Set  reqInterval: " + reqInterval);
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
	 * Sets the {@code selectedSubAttrValues} property to {@code ArrayList<SubAttrValues>} argument.
	 * 
	 * @param selectedSubAttrValues
	 */
	public void setSelectedSubAttrValues(
			ArrayList<SubAttrValues> selectedSubAttrValues) {
		this.selectedSubAttrValues = selectedSubAttrValues;
		log.debug("Set  selectedSubAttrValues: " + selectedSubAttrValues);
	}
	/**
	 * Sets the {@code selectedSubMatchIds} property to {@code ArrayList<String>} argument.
	 * 
	 * @param selectedSubMatchIds
	 */
	public void setSelectedSubMatchIds(ArrayList<String> selectedSubMatchIds) {
		this.selectedSubMatchIds = selectedSubMatchIds;
		log.debug("Set  selectedSubMatchIds: " + selectedSubMatchIds);
	}
	/**
	 * Sets the {@code selectedResAttrValues} property to {@code ArrayList<ResAttrValues>} argument.
	 * 
	 * @param selectedResAttrValues
	 */
	public void setSelectedResAttrValues(
			ArrayList<ResAttrValues> selectedResAttrValues) {
		this.selectedResAttrValues = selectedResAttrValues;
		log.debug("Set  selectedResAttrValues: " + selectedResAttrValues);
	}
	/**
	 * Sets the {@code selectedResMatchIds} property to {@code ArrayList<String>} argument.
	 * 
	 * @param selectedResMatchIds
	 */
	public void setSelectedResMatchIds(ArrayList<String> selectedResMatchIds) {
		this.selectedResMatchIds = selectedResMatchIds;
		log.debug("Set  selectedResMatchIds: " + selectedResMatchIds);
	}
	/**
	 * Sets the {@code selectedActAttrValues} property to {@code ArrayList<ActAttrValues>} argument.
	 * 
	 * @param selectedActAttrValues
	 */
	public void setSelectedActAttrValues(
			ArrayList<ActAttrValues> selectedActAttrValues) {
		this.selectedActAttrValues = selectedActAttrValues;
		log.debug("Set  selectedActAttrValues: " + selectedActAttrValues);
	}
	/**
	 * Sets the {@code selectedActMatchIds} property to {@code ArrayList<String>} argument.
	 * 
	 * @param selectedActMatchIds
	 */
	public void setSelectedActMatchIds(ArrayList<String> selectedActMatchIds) {
		this.selectedActMatchIds = selectedActMatchIds;
		log.debug("Set  selectedActMatchIds: " + selectedActMatchIds);
	}
	/**
	 * Sets the {@code selectedEnvAttrValues} property to {@code ArrayList<EnvAttrValues>} argument.
	 * 
	 * @param selectedEnvAttrValues
	 */
	public void setSelectedEnvAttrValues(
			ArrayList<EnvAttrValues> selectedEnvAttrValues) {
		this.selectedEnvAttrValues = selectedEnvAttrValues;
		log.debug("Set  selectedEnvAttrValues: " + selectedEnvAttrValues);
	}
	/**
	 * Sets the {@code selectedEnvMatchIds} property to {@code ArrayList<String>} argument.
	 * 
	 * @param selectedEnvMatchIds
	 */
	public void setSelectedEnvMatchIds(ArrayList<String> selectedEnvMatchIds) {
		this.selectedEnvMatchIds = selectedEnvMatchIds;
		log.debug("Set  selectedEnvMatchIds: " + selectedEnvMatchIds);
	}
	/**
	 * Sets the {@code rootApply} property to {@code Apply} argument.
	 * 
	 * @param rootApply
	 */
	public void setRootApply(Apply rootApply) {
		this.rootApply = rootApply;
		log.debug("Set  rootApply: " + rootApply);
	}
	/**
	 * Sets the {@code policyDao} property to {@code PolicyDAO} argument.
	 * 
	 * @param policyDao
	 */
	public void setPolicyDao(PolicyDAO policyDao) {
		this.policyDao = policyDao;
		log.debug("Set  policyDao: " + policyDao);
	}
	/**
	 * Sets the {@code onGoingTimes} property to {@code List<String>} argument.
	 * 
	 * @param onGoingTimes
	 */
	public void setOnGoingTimes(List<String> onGoingTimes) {
		this.onGoingTimes = onGoingTimes;
		log.debug("Set  onGoingTimes: " + onGoingTimes);
	}
	/**
	 * Sets the {@code number} property to {@code ArrayList<String>} argument.
	 * 
	 * @param number
	 */
	public void setNumber(ArrayList<String> number) {
		this.number = number;
		log.debug("Set  number: " + number);
	}
	/**
	 * Sets the {@code newNode} property to {@code ArrayList<TreeNode>} argument.
	 * 
	 * @param newNode
	 */
	public void setNewNode(ArrayList<TreeNode> newNode) {
		this.newNode = newNode;
		log.debug("Set  newNode: " + newNode);
	}
	
	
	/**
	 * Sets the {@code functionOneArg} property to {@code List<String>} argument.
	 * 
	 * @param functionOneArg
	 */
	public void setFunctionOneArg(List<String> functionOneArg) {
		this.functionOneArg = functionOneArg;
		log.debug("Set  functionOneArg: " + functionOneArg);
	}
	/**
	 * Sets the {@code daoSubject} property to {@code SubjectDAO} argument.
	 * 
	 * @param daoSubject
	 */
	public void setDaoSubject(SubjectDAO daoSubject) {
		this.daoSubject = daoSubject;
		log.debug("Set  daoSubject: " + daoSubject);
	}
	/**
	 * Sets the {@code daoSubjectAttribute} property to {@code SubjectAttributeDAO} argument.
	 * 
	 * @param daoSubjectAttribute
	 */
	public void setDaoSubjectAttribute(SubjectAttributeDAO daoSubjectAttribute) {
		this.daoSubjectAttribute = daoSubjectAttribute;
		log.debug("Set  daoSubjectAttribute: " + daoSubjectAttribute);
	}
	/**
	 * Sets the {@code daoSubjectAttributeValue} property to {@code SubAttrValuesDAO} argument.
	 * 
	 * @param daoSubjectAttributeValue
	 */
	public void setDaoSubjectAttributeValue(
			SubAttrValuesDAO daoSubjectAttributeValue) {
		this.daoSubjectAttributeValue = daoSubjectAttributeValue;
		log.debug("Set  daoSubjectAttributeValue: " + daoSubjectAttributeValue);
	}
	/**
	 * Sets the {@code daoRes} property to {@code ResourceDAO} argument.
	 * 
	 * @param daoRes
	 */
	public void setDaoRes(ResourceDAO daoRes) {
		this.daoRes = daoRes;
		log.debug("Set  daoRes: " + daoRes);
	}
	/**
	 * Sets the {@code daoResourceAttribute} property to {@code ResourceAttributeDAO} argument.
	 * 
	 * @param daoResourceAttribute
	 */
	public void setDaoResourceAttribute(ResourceAttributeDAO daoResourceAttribute) {
		this.daoResourceAttribute = daoResourceAttribute;
		log.debug("Set  daoResourceAttribute: " + daoResourceAttribute);
	}
	/**
	 * Sets the {@code daoResourceAttributeValue} property to {@code ResAttrValuesDAO} argument.
	 * 
	 * @param daoResourceAttributeValue
	 */
	public void setDaoResourceAttributeValue(
			ResAttrValuesDAO daoResourceAttributeValue) {
		this.daoResourceAttributeValue = daoResourceAttributeValue;
		log.debug("Set  daoResourceAttributeValue: " + daoResourceAttributeValue);
	}
	/**
	 * Sets the {@code daoAction} property to {@code ActionDAO} argument.
	 * 
	 * @param daoAction
	 */
	public void setDaoAction(ActionDAO daoAction) {
		this.daoAction = daoAction;
		log.debug("Set  daoAction: " + daoAction);
	}
	/**
	 * Sets the {@code daoActionAttribute} property to {@code ActionAttributeDAO} argument.
	 * 
	 * @param daoActionAttribute
	 */
	public void setDaoActionAttribute(ActionAttributeDAO daoActionAttribute) {
		this.daoActionAttribute = daoActionAttribute;
		log.debug("Set  daoActionAttribute: " + daoActionAttribute);
	}
	/**
	 * Sets the {@code daoActionAttributeValue} property to {@code ActAttrValuesDAO} argument.
	 * 
	 * @param daoActionAttributeValue
	 */
	public void setDaoActionAttributeValue(ActAttrValuesDAO daoActionAttributeValue) {
		this.daoActionAttributeValue = daoActionAttributeValue;
		log.debug("Set  daoActionAttributeValue: " + daoActionAttributeValue);
	}
	/**
	 * Sets the {@code daoEnv} property to {@code EnvironmentDAO} argument.
	 * 
	 * @param daoEnv
	 */
	public void setDaoEnv(EnvironmentDAO daoEnv) {
		this.daoEnv = daoEnv;
		log.debug("Set  daoEnv: " + daoEnv);
	}
	/**
	 * Sets the {@code envattrdao} property to {@code EnvironmentAttributeDAO} argument.
	 * 
	 * @param envattrdao
	 */
	public void setEnvattrdao(EnvironmentAttributeDAO envattrdao) {
		this.envattrdao = envattrdao;
		log.debug("Set  envattrdao: " + envattrdao);
	}
	/**
	 * Sets the {@code envattrvaluesdao} property to {@code EnvAttrValuesDAO} argument.
	 * 
	 * @param envattrvaluesdao
	 */
	public void setEnvattrvaluesdao(EnvAttrValuesDAO envattrvaluesdao) {
		this.envattrvaluesdao = envattrvaluesdao;
		log.debug("Set  envattrvaluesdao: " + envattrvaluesdao);
	}
	/**
	 * Sets the {@code createdExpression} property to {@code ArrayList<Expression>} argument.
	 * 
	 * @param createdExpression
	 */
	public void setCreatedExpression(ArrayList<Expression> createdExpression) {
		this.createdExpression = createdExpression;
		log.debug("Set  createdExpression: " + createdExpression);
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
	 * Sets the {@code opertionFail} property to {@code boolean} argument.
	 * 
	 * @param opertionFail
	 */
	public void setOpertionFail(boolean opertionFail) {
		this.opertionFail = opertionFail;
		log.debug("Set  opertionFail: " + opertionFail);
	}
	/**
	 * Sets the {@code addbtn} property to {@code boolean} argument.
	 * 
	 * @param addbtn
	 */
	public void setAddbtn(boolean addbtn) {
		this.addbtn = addbtn;
		log.debug("Set  addbtn: " + addbtn);

	}
	
	
	
	
	
	/**
	 * Sets the {@code allTargSubjects} property to {@code ArrayList<Subjects>} argument.
	 * 
	 * @param allTargSubjects
	 */
	public void setAllTargSubjects(ArrayList<Subjects> allTargSubjects) {
		this.allTargSubjects = allTargSubjects;
		log.debug("Set  allTargSubjects: " + allTargSubjects);
	}
	/**
	 * Sets the {@code allTargResources} property to {@code ArrayList<Resources>} argument.
	 * 
	 * @param allTargResources
	 */
	public void setAllTargResources(ArrayList<Resources> allTargResources) {
		this.allTargResources = allTargResources;
		log.debug("Set  allTargResources: " + allTargResources);
	}
	/**
	 * Sets the {@code allTargActions} property to {@code ArrayList<Actions>} argument.
	 * 
	 * @param allTargActions
	 */
	public void setAllTargActions(ArrayList<Actions> allTargActions) {
		this.allTargActions = allTargActions;
		log.debug("Set  allTargActions: " + allTargActions);
	}
	/**
	 * Sets the {@code allTargEnvironments} property to {@code ArrayList<Environments>} argument.
	 * 
	 * @param allTargEnvironments
	 */
	public void setAllTargEnvironments(
			ArrayList<Environments> allTargEnvironments) {
		this.allTargEnvironments = allTargEnvironments;
		log.debug("Set  allTargEnvironments: " + allTargEnvironments);
	}
	
	
	
	
	/**
	 * Sets the {@code allTarget} property to {@code ArrayList<Target>} argument.
	 * 
	 * @param allTarget
	 */
	public void setAllTarget(ArrayList<Target> allTarget) {
		this.allTarget = allTarget;
		log.debug("Set  allTarget: " + allTarget);
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
	 * Sets the {@code selectedSubValue} property to {@code Condition} argument.
	 * 
	 * @param selectedSubValue
	 */
	public void setSelectedSubValue(SubAttrValues selectedSubValue) {
		this.selectedSubValue = selectedSubValue;
		log.debug("Set  selectedSubValue: " + selectedSubValue);

	}
	/**
	 * Sets the {@code selectedActValue} property to {@code ActAttrValues} argument.
	 * 
	 * @param selectedActValue
	 */
	public void setSelectedActValue(ActAttrValues selectedActValue) {
		this.selectedActValue = selectedActValue;
		log.debug("Set  selectedActValue: " + selectedActValue);
	}
	/**
	 * Sets the {@code selectedResValue} property to {@code ResAttrValues} argument.
	 * 
	 * @param selectedResValue
	 */
	public void setSelectedResValue(ResAttrValues selectedResValue) {
		this.selectedResValue = selectedResValue;
		log.debug("Set  selectedResValue: " + selectedResValue);
	}
	/**
	 * Sets the {@code selectedEnvValue} property to {@code EnvAttrValues} argument.
	 * 
	 * @param selectedEnvValue
	 */
	public void setSelectedEnvValue(EnvAttrValues selectedEnvValue) {
		this.selectedEnvValue = selectedEnvValue;
		log.debug("Set  selectedEnvValue: " + selectedEnvValue);
	}
	/**
	 * Sets the {@code selectedAction} property to {@code Action} argument.
	 * 
	 * @param selectedAction
	 */
	public void setSelectedAction(Action selectedAction) {
		this.selectedAction = selectedAction;
		this.selectedActValue = null;
		this.setSelectedActionAttributes(null);
		log.debug("Set  selectedAction: " + selectedAction);
	}
	/**
	 * Sets the {@code selectedActionAttributes} property to {@code ActionAttribute} argument.
	 * 
	 * @param selectedActionAttributes
	 */
	public void setSelectedActionAttributes(
			ActionAttribute selectedActionAttributes) {
		this.selectedActionAttributes = selectedActionAttributes;
		log.debug("Set  selectedActionAttributes: " + selectedActionAttributes);
	}
	/**
	 * Sets the {@code description} property to {@code String} argument.
	 * 
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
		log.debug("Set  description: " + description);

	}
	/**
	 * Sets the {@code selectedSubAttValue} property to {@code String} argument.
	 * 
	 * @param selectedSubAttValue
	 */
	public void setSelectedSubAttValue(String selectedSubAttValue) {
		this.selectedSubAttValue = selectedSubAttValue;
		log.debug("Set  selectedSubAttValue: " + selectedSubAttValue);
	}
	
	
	
	/**
	 * Sets the {@code allResAttributes} property to {@code ArrayList<ResourceAttribute>} argument.
	 * 
	 * @param allResAttributes
	 */
	public void setAllResAttributes(ArrayList<ResourceAttribute> allResAttributes) {
		this.allResAttributes = allResAttributes;
		log.debug("Set  allResAttributes: " + allResAttributes);
	}
	/**
	 * Sets the {@code targetSubjects} property to {@code ArrayList<Subject>} argument.
	 * 
	 * @param targetSubjects
	 */
	public void setTargetSubjects(ArrayList<Subject> targetSubjects) {
		this.targetSubjects = targetSubjects;
		log.debug("Set  targetSubjects: " + targetSubjects);
	}
	/**
	 * Sets the {@code targetResources} property to {@code ArrayList<Resource>} argument.
	 * 
	 * @param targetResources
	 */
	public void setTargetResources(ArrayList<Resource> targetResources) {
		this.targetResources = targetResources;
		log.debug("Set  targetResources: " + targetResources);
	}
	/**
	 * Sets the {@code targetActions} property to {@code ArrayList<Action>} argument.
	 * 
	 * @param targetActions
	 */
	public void setTargetActions(ArrayList<Action> targetActions) {
		this.targetActions = targetActions;
		log.debug("Set  targetActions: " + targetActions);
	}
	/**
	 * Sets the {@code matchIds} property to {@code ArrayList<String>} argument.
	 * 
	 * @param matchIds
	 */
	public static void setMatchIds(ArrayList<String> matchIds) {
		UconPolicyWizardController.matchIds = matchIds;
		log.debug("Set  matchIds: " + matchIds);
	}
	/**
	 * Sets the {@code targetEnvironments} property to {@code ArrayList<Environment>} argument.
	 * 
	 * @param targetEnvironments
	 */
	public void setTargetEnvironments(ArrayList<Environment> targetEnvironments) {
		this.targetEnvironments = targetEnvironments;
		log.debug("Set  targetEnvironments: " + targetEnvironments);
	}
	/**
	 * Sets the {@code dao} property to {@code TargetDAO} argument.
	 * 
	 * @param dao
	 */
	public void setDao(TargetDAO dao) {
		this.dao = dao;
		log.debug("Set  dao: " + dao);
	}
	/**
	 * Sets the {@code selectedSubject} property to {@code Subject} argument.
	 * 
	 * @param selectedSubject
	 */
	public void setSelectedSubject(Subject selectedSubject) {
		this.selectedSubject = selectedSubject;
		this.selectedSubValue = null;
		this.setSelectedSubjectAttributes(null);
		log.debug("Set  selectedSubject: " + selectedSubject);
	}
	
	
	
	/**
	 * Sets the {@code selectedResource} property to {@code Resource} argument.
	 * 
	 * @param selectedResource
	 */
	public void setSelectedResource(Resource selectedResource) {
		this.selectedResource = selectedResource;
		this.selectedResValue = null;
		this.setSelectedResourceAttribute(null);
		log.debug("Set  selectedResource: " + selectedResource);
	}
	/**
	 * Sets the {@code allSubAttributes} property to {@code ArrayList<SubjectAttribute>} argument.
	 * 
	 * @param allSubAttributes
	 */
	public void setAllSubAttributes(ArrayList<SubjectAttribute> allSubAttributes) {
		this.allSubAttributes = allSubAttributes;
		log.debug("Set  allSubAttributes: " + allSubAttributes);
	}
	/**
	 * Sets the {@code allSubValues} property to {@code ArrayList<SubAttrValues>} argument.
	 * 
	 * @param allSubValues
	 */
	public void setAllSubValues(ArrayList<SubAttrValues> allSubValues) {
		this.allSubValues = allSubValues;
		log.debug("Set  allSubValues: " + allSubValues);
	}
	/**
	 * Sets the {@code allResValues} property to {@code ArrayList<ResAttrValues>} argument.
	 * 
	 * @param allResValues
	 */
	public void setAllResValues(ArrayList<ResAttrValues> allResValues) {
		this.allResValues = allResValues;
		log.debug("Set  allResValues: " + allResValues);
	}
	/**
	 * Sets the {@code selectedSubjectAttributes} property to {@code SubjectAttribute} argument.
	 * 
	 * @param selectedSubjectAttributes
	 */
	public void setSelectedSubjectAttributes(
			SubjectAttribute selectedSubjectAttributes) {
		this.selectedSubjectAttributes = selectedSubjectAttributes;
		log.debug("Set  selectedSubjectAttributes: " + selectedSubjectAttributes);
	}
	/**
	 * Sets the {@code selectedResourceAttributes} property to {@code ResourceAttribute} argument.
	 * 
	 * @param selectedResourceAttributes
	 */
	public void setSelectedResourceAttribute(
			ResourceAttribute selectedResourceAttributes) {
		this.selectedResourceAttribute = selectedResourceAttributes;
		log.debug("Set  selectedResourceAttributes: " + selectedResourceAttributes);
	}
	/**
	 * Sets the {@code allActValues} property to {@code ArrayList<ActAttrValues>} argument.
	 * 
	 * @param allActValues
	 */
	public void setAllActValues(ArrayList<ActAttrValues> allActValues) {
		this.allActValues = allActValues;
		log.debug("Set  allActValues: " + allActValues);
	}
	/**
	 * Sets the {@code selectedEnvironment} property to {@code Environment} argument.
	 * 
	 * @param selectedEnvironment
	 */
	public void setSelectedEnvironment(Environment selectedEnvironment) {
		this.selectedEnvironment = selectedEnvironment;
		this.selectedEnvValue = null;
		this.setSelectedEnvironmentAttribute(null);
		log.debug("Set  selectedEnvironment: " + selectedEnvironment);
	}
	/**
	 * Sets the {@code selectedEnvironmentAttribute} property to {@code EnvironmentAttribute} argument.
	 * 
	 * @param selectedEnvironmentAttribute
	 */
	public void setSelectedEnvironmentAttribute(
			EnvironmentAttribute selectedEnvironmentAttribute) {
		this.selectedEnvironmentAttribute = selectedEnvironmentAttribute;
		log.debug("Set  selectedEnvironmentAttribute: " + selectedEnvironmentAttribute);
	}
	/**
	 * Sets the {@code allEnvValues} property to {@code ArrayList<EnvAttrValues>} argument.
	 * 
	 * @param allEnvValues
	 */
	public void setAllEnvValues(ArrayList<EnvAttrValues> allEnvValues) {
		this.allEnvValues = allEnvValues;
		log.debug("Set  allEnvValues: " + allEnvValues);
	}
	/**
	 * Sets the {@code selectedMatchId} property to {@code String} argument.
	 * 
	 * @param selectedMatchId
	 */
	public void setSelectedMatchId(String selectedMatchId) {
		this.selectedMatchId = selectedMatchId;
		log.debug("Set  selectedMatchId: " + selectedMatchId);
	}
	
	
	
	/**
	 * Sets the {@code updatedDescription} property to {@code String} argument.
	 * 
	 * @param updatedDescription
	 */
	public void setUpdatedDescription(String updatedDescription) {
		this.updatedDescription = updatedDescription;
		log.debug("Set  updatedDescription: " + updatedDescription);
	}
	/**
	 * Sets the {@code updatedTargetId} property to {@code String} argument.
	 * 
	 * @param updatedTargetId
	 */
	public void setUpdatedTargetId(String updatedTargetId) {
		this.updatedTargetId = updatedTargetId;
		log.debug("Set  updatedTargetId: " + updatedTargetId);
	}
	
	/**
	 * Sets the {@code selectedSubjects} property to {@code Subjects} argument.
	 * 
	 * @param selectedSubjects
	 */
	public void setSelectedSubjects(Subjects selectedSubjects) {
		this.selectedSubjects = selectedSubjects;
		if (clickedTarget != null && this.selectedSubjects != null) {
			if (subjListTarg == null) {
				subjListTarg = addForSubjectMatch();
				if (subjListTarg == null)
					subjListTarg = new ArrayList<Object[]>();
			}
			if (subjListTarg.size() <= 0)
				System.out.println("It was also Zero !!");
			List<SubjectMatch> subjectMatch = dao.createSubjectMatchForUpdate(
					subjListTarg, this.isMustBePresent());
			if (subjectMatch == null) {

				subjectMatch = new ArrayList<SubjectMatch>();
			}
			if (subjectMatch.size() <= 0)
				System.out.println("It was Zero !!");
			Subject sb = dao
					.getSubjectFromSubjects(clickedTarget.getPkTarget(),
							selectedSubjects, subjectMatch);
			subjListTarg = null;

			this.setAddedTargetSubject(sb);
		}
		log.debug("Set  selectedSubjects: " + selectedSubjects);
	}
	/**
	 * Sets the {@code selectedResources} property to {@code Resources} argument.
	 * 
	 * @param selectedResources
	 */
	public void setSelectedResources(Resources selectedResources) {
		this.selectedResources = selectedResources;
		if (clickedTarget != null && this.selectedResources != null) {
			Resource rs = dao.getResourceFromResources(
					clickedTarget.getPkTarget(), this.selectedResources);
			this.setAddedTargetResource(rs);
			
		}
		log.debug("Set  selectedResources: " + selectedResources);
	}
	/**
	 * Sets the {@code selectedActions} property to {@code Actions} argument.
	 * 
	 * @param selectedActions
	 */
	public void setSelectedActions(Actions selectedActions) {
		this.selectedActions = selectedActions;
		if (clickedTarget != null && this.selectedActions != null) {

			Action act = dao.getActionFromActions(clickedTarget.getPkTarget(),
					this.selectedActions);
			this.setAddedTargetAction(act);
		}
		log.debug("Set  selectedActions: " + selectedActions);
	}
	/**
	 * Sets the {@code selectedEnvironments} property to {@code Environments} argument.
	 * 
	 * @param selectedEnvironments
	 */
	public void setSelectedEnvironments(Environments selectedEnvironments) {
		this.selectedEnvironments = selectedEnvironments;
		if (clickedTarget != null && this.selectedEnvironments != null) {

			Environment env = dao.getEnvironmentByEnvironments(
					clickedTarget.getPkTarget(), this.selectedEnvironments);
			this.setAddedTargetEnvironment(env);
		}
		log.debug("Set  selectedEnvironments: " + selectedEnvironments);
	}
	/**
	 * Sets the {@code addedTargetSubject} property to {@code Subject} argument.
	 * 
	 * @param addedTargetSubject
	 */
	public void setAddedTargetSubject(Subject addedTargetSubject) {
		this.addedTargetSubject = addedTargetSubject;
		log.debug("Set  addedTargetSubject: " + addedTargetSubject);
	}
	/**
	 * Sets the {@code addedTargetResource} property to {@code Resource} argument.
	 * 
	 * @param addedTargetResource
	 */
	public void setAddedTargetResource(Resource addedTargetResource) {
		this.addedTargetResource = addedTargetResource;
		log.debug("Set  addedTargetResource: " + addedTargetResource);
	}
	/**
	 * Sets the {@code addedTargetAction} property to {@code Action} argument.
	 * 
	 * @param addedTargetAction
	 */
	public void setAddedTargetAction(Action addedTargetAction) {
		this.addedTargetAction = addedTargetAction;
		log.debug("Set  addedTargetAction: " + addedTargetAction);
	}
	/**
	 * Sets the {@code addedTargetEnvironment} property to {@code Environment} argument.
	 * 
	 * @param addedTargetEnvironment
	 */
	public void setAddedTargetEnvironment(Environment addedTargetEnvironment) {
		this.addedTargetEnvironment = addedTargetEnvironment;
		log.debug("Set  addedTargetEnvironment: " + addedTargetEnvironment);
	}
	/**
	 * Sets the {@code mustBePresent} property to {@code boolean} argument.
	 * 
	 * @param mustBePresent
	 */
	public void setMustBePresent(boolean mustBePresent) {
		this.mustBePresent = mustBePresent;
		log.debug("Set  mustBePresent: " + mustBePresent);
	}
	/**
	 * Sets the {@code policyName} property to {@code String} argument.
	 * 
	 * @param policyName
	 */
	public void setPolicyName(String policyName) {
		this.policyName = policyName;
		log.debug("Set  policyName: " + policyName);
	}
	/**
	 * Sets the {@code algorithmList} property to {@code List<String>} argument.
	 * 
	 * @param algorithmList
	 */
	public void setAlgorithmList(List<String> algorithmList) {
		this.algorithmList = algorithmList;
		log.debug("Set  algorithmList: " + algorithmList);
	}
	/**
	 * Sets the {@code policyDescription} property to {@code String} argument.
	 * 
	 * @param policyDescription
	 */
	public void setPolicyDescription(String policyDescription) {
		this.policyDescription = policyDescription;
		log.debug("Set  policyDescription: " + policyDescription);
	}
	/**
	 * Sets the {@code appliedAlgo} property to {@code String} argument.
	 * 
	 * @param appliedAlgo
	 */
	public void setAppliedAlgo(String appliedAlgo) {
		this.appliedAlgo = appliedAlgo;
		log.debug("Set  appliedAlgo: " + appliedAlgo);
	}
	/**
	 * Sets the {@code onGoingTime} property to {@code String} argument.
	 * 
	 * @param onGoingTime
	 */
	public void setOnGoingTime(String onGoingTime) {
		this.onGoingTime = onGoingTime;
		log.debug("Set  onGoingTime: " + onGoingTime);
	}
	/**
	 * Sets the {@code attrIds} property to {@code List<String>} argument.
	 * 
	 * @param attrIds
	 */
	public void setAttrIds(List<String> attrIds) {
		this.attrIds = attrIds;
		log.debug("Set  attrIds: " + attrIds);
	}
	/**
	 * Sets the {@code onGoingAttrIds} property to {@code List<String>} argument.
	 * 
	 * @param onGoingAttrIds
	 */
	public void setOnGoingAttrIds(List<String> onGoingAttrIds) {
		this.onGoingAttrIds = onGoingAttrIds;
		log.debug("Set  onGoingAttrIds: " + onGoingAttrIds);
	}
	/**
	 * Sets the {@code postAttrIds} property to {@code List<String>} argument.
	 * 
	 * @param postAttrIds
	 */
	public void setPostAttrIds(List<String> postAttrIds) {
		this.postAttrIds = postAttrIds;
		log.debug("Set  postAttrIds: " + postAttrIds);
	}
	/**
	 * Sets the {@code selectedPreUpdate} property to {@code selectedPreUpdate} argument.
	 * 
	 * @param selectedPreUpdate
	 */
	public void setSelectedPreUpdate(AttributeAssignment selectedPreUpdate) {
		this.selectedPreUpdate = selectedPreUpdate;
		log.debug("Set  selectedPreUpdate: " + selectedPreUpdate);

	}
	/**
	 * Sets the {@code selectedOnGoingUpdate} property to {@code AttributeAssignment} argument.
	 * 
	 * @param selectedOnGoingUpdate
	 */
	public void setSelectedOnGoingUpdate(
			AttributeAssignment selectedOnGoingUpdate) {
		this.selectedOnGoingUpdate = selectedOnGoingUpdate;
		log.debug("Set  selectedOnGoingUpdate: " + selectedOnGoingUpdate);
	}
	/**
	 * Sets the {@code selectedPostUpdate} property to {@code AttributeAssignment} argument.
	 * 
	 * @param selectedPostUpdate
	 */
	public void setSelectedPostUpdate(AttributeAssignment selectedPostUpdate) {
		this.selectedPostUpdate = selectedPostUpdate;
		log.debug("Set  selectedPostUpdate: " + selectedPostUpdate);
	}
	/**
	 * Sets the {@code preUpdateCheckBox} property to {@code boolean} argument.
	 * 
	 * @param preUpdateCheckBox
	 */
	public void setPreUpdateCheckBox(boolean preUpdateCheckBox) {
		this.preUpdateCheckBox = preUpdateCheckBox;
		log.debug("Set  preUpdateCheckBox: " + preUpdateCheckBox);
	}
	/**
	 * Sets the {@code onGoingUpdateCheckBox} property to {@code boolean} argument.
	 * 
	 * @param onGoingUpdateCheckBox
	 */
	public void setOnGoingUpdateCheckBox(boolean onGoingUpdateCheckBox) {
		this.onGoingUpdateCheckBox = onGoingUpdateCheckBox;
		if(!this.on)
			this.on = this.onGoingUpdateCheckBox;
		log.debug("Set  onGoingUpdateCheckBox: " + onGoingUpdateCheckBox);
	}
	/**
	 * Sets the {@code postUpdateCheckBox} property to {@code boolean} argument.
	 * 
	 * @param postUpdateCheckBox
	 */
	public void setPostUpdateCheckBox(boolean postUpdateCheckBox) {
		this.postUpdateCheckBox = postUpdateCheckBox;
		log.debug("Set  postUpdateCheckBox: " + postUpdateCheckBox);
	}
	/**
	 * Sets the {@code preAttrId} property to {@code String} argument.
	 * 
	 * @param preAttrId
	 */
	public void setPreAttrId(String preAttrId) {
		this.preAttrId = preAttrId;
		log.debug("Set  preAttrId: " + preAttrId);
	}
	/**
	 * Sets the {@code preValue} property to {@code String} argument.
	 * 
	 * @param preValue
	 */
	public void setPreValue(String preValue) {
		this.preValue = preValue;
		log.debug("Set  preValue: " + preValue);
	}
	/**
	 * Sets the {@code preValues} property to {@code List<AttributeAssignment>} argument.
	 * 
	 * @param preValues
	 */
	public void setPreValues(List<AttributeAssignment> preValues) {
		this.preValues = preValues;
		log.debug("Set  preValues: " + preValues);
	}
	/**
	 * Sets the {@code onGoingAttrId} property to {@code String} argument.
	 * 
	 * @param onGoingAttrId
	 */
	public void setOnGoingAttrId(String onGoingAttrId) {
		this.onGoingAttrId = onGoingAttrId;
		log.debug("Set  onGoingAttrId: " + onGoingAttrId);
	}
	/**
	 * Sets the {@code onGoingValue} property to {@code String} argument.
	 * 
	 * @param onGoingValue
	 */
	public void setOnGoingValue(String onGoingValue) {
		this.onGoingValue = onGoingValue;
		log.debug("Set  onGoingValue: " + onGoingValue);
	}
	/**
	 * Sets the {@code onGoingValues} property to {@code List<AttributeAssignment>} argument.
	 * 
	 * @param onGoingValues
	 */
	public void setOnGoingValues(List<AttributeAssignment> onGoingValues) {
		this.onGoingValues = onGoingValues;
		log.debug("Set  onGoingValues: " + onGoingValues);
	}
	/**
	 * Sets the {@code postAttrId} property to {@code String} argument.
	 * 
	 * @param postAttrId
	 */
	public void setPostAttrId(String postAttrId) {
		this.postAttrId = postAttrId;
		log.debug("Set  postAttrId: " + postAttrId);
	}
	/**
	 * Sets the {@code postValue} property to {@code String} argument.
	 * 
	 * @param postValue
	 */
	public void setPostValue(String postValue) {
		this.postValue = postValue;
		log.debug("Set  postValue: " + postValue);
	}
	/**
	 * Sets the {@code postValues} property to {@code List<AttributeAssignment>} argument.
	 * 
	 * @param postValues
	 */
	public void setPostValues(List<AttributeAssignment> postValues) {
		this.postValues = postValues;
		log.debug("Set  postValues: " + postValues);
	}
	/**
	 * Sets the {@code dataTypes} property to {@code List<String>} argument.
	 * 
	 * @param dataTypes
	 */
	public void setDataTypes(List<String> dataTypes) {
		this.dataTypes = dataTypes;
		log.debug("Set  dataTypes: " + dataTypes);
	}
	/**
	 * Sets the {@code pre} property to {@code boolean} argument.
	 * 
	 * @param pre
	 */
	public void setPre(boolean pre) {
		this.pre = pre;
		log.debug("Set  pre: " + pre);
	}
	/**
	 * Sets the {@code on} property to {@code boolean} argument.
	 * 
	 * @param on
	 */
	public void setOn(boolean on) {
		this.on = on;
		log.debug("Set  on: " + on);
	}
	/**
	 * Sets the {@code onGoingReqOrUpdate} property to {@code boolean} argument.
	 * 
	 * @param onGoingReqOrUpdate
	 */
	public void setOnGoingReqOrUpdate(boolean onGoingReqOrUpdate) {
		this.onGoingReqOrUpdate = onGoingReqOrUpdate;
		log.debug("Set  onGoingReqOrUpdate: " + onGoingReqOrUpdate);
	}
	/**
	 * Sets the {@code selectedCondition} property to {@code Condition} argument.
	 * 
	 * @param selectedCondition
	 */
	public void setSelectedCondition(Condition selectedCondition) {
		this.selectedCondition = selectedCondition;
		log.debug("Set  selectedCondition: " + selectedCondition);
	}
	/**
	 * Sets the {@code conditionDao} property to {@code ConditionDAO} argument.
	 * 
	 * @param conditionDao
	 */
	public void setConditionDao(ConditionDAO conditionDao) {
		this.conditionDao = conditionDao;
		log.debug("Set  conditionDao: " + conditionDao);
	}
	/**
	 * Sets the {@code allCondition} property to {@code ArrayList<Condition>} argument.
	 * 
	 * @param allCondition
	 */
	public void setAllCondition(ArrayList<Condition> allCondition) {
		this.allCondition = allCondition;
		log.debug("Set  allCondition: " + allCondition);
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
		log.debug("Set  designatorId: " + designatorId);
	}
	/**
	 * Sets the {@code designatorType} property to {@code String} argument.
	 * 
	 * @param designatorType
	 */
	public void setDesignatorType(String designatorType) {
		this.designatorType = designatorType;
		log.debug("Set  designatorType: " + designatorType);
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
	 * Sets the {@code applyFuncId} property to {@code String} argument.
	 * 
	 * @param applyFuncId
	 */
	public void setApplyFuncId(String applyFuncId) {
		this.applyFuncId = applyFuncId;
		log.debug("Set  applyFuncId: " + applyFuncId);
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
	 * Sets the {@code apply} property to {@code Apply} argument.
	 * 
	 * @param apply
	 */
	public void setApply(Apply apply) {
		this.apply = apply;
		log.debug("Set  apply: " + apply);
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
	 * Sets the {@code root} property to {@code TreeNode} argument.
	 * 
	 * @param root
	 */
	public void setRoot(TreeNode root) {
		this.root = root;
		log.debug("Set  root: " + root);
	}
	/**
	 * Sets the {@code selectedNode} property to {@code TreeNode} argument.
	 * 
	 * @param selectedNode
	 */
	public void setSelectedNode(TreeNode selectedNode) {
		this.selectedNode = selectedNode;
		log.debug("Set  selectedNode: " + selectedNode);
	}
	/**
	 * Sets the {@code attributeDesignatorId} property to {@code String} argument.
	 * 
	 * @param attributeDesignatorId
	 */
	public void setAttributeDesignatorId(String attributeDesignatorId) {
		this.attributeDesignatorId = attributeDesignatorId;
		log.debug("Set  attributeDesignatorId: " + attributeDesignatorId);
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
	 * Sets the {@code targetWithNoEnvironment} property to {@code ArrayList<Target>} argument.
	 * 
	 * @param targetWithNoEnvironment
	 */
	public void setTargetWithNoEnvironment(
			ArrayList<Target> targetWithNoEnvironment) {
		this.targetWithNoEnvironment = targetWithNoEnvironment;
		log.debug("Set  targetWithNoEnvironment: " + targetWithNoEnvironment);
	}
	/**
	 * Sets the {@code preABC} property to {@code String} argument.
	 * 
	 * @param preABC
	 */
	public void setPreABC(String preABC) {
		this.preABC = preABC;
		log.debug("Set  preABC: " + preABC);
	}
	/**
	 * Sets the {@code onGoingABC} property to {@code String} argument.
	 * 
	 * @param onGoingABC
	 */
	public void setOnGoingABC(String onGoingABC) {
		this.onGoingABC = onGoingABC;
		log.debug("Set  onGoingABC: " + onGoingABC);
	}
	/**
	 * Sets the {@code clickedOblTarget} property to {@code Target} argument.
	 * 
	 * @param clickedOblTarget
	 */
	public void setClickedOblTarget(Target clickedOblTarget) {
		this.clickedOblTarget = clickedOblTarget;
		log.debug("Set  clickedOblTarget: " + clickedOblTarget);
	}
	/**
	 * Sets the {@code allOblTarget} property to {@code ArrayList<Target>} argument.
	 * 
	 * @param allOblTarget
	 */
	public void setAllOblTarget(ArrayList<Target> allOblTarget) {
		this.allOblTarget = allOblTarget;
		log.debug("Set  allOblTarget: " + allOblTarget);
	}
	/**
	 * Sets the {@code abcPropertiesCond} property to {@code boolean} argument.
	 * 
	 * @param abcPropertiesCond
	 */
	public void setAbcPropertiesCond(boolean abcPropertiesCond) {
		this.abcPropertiesCond = abcPropertiesCond;
		log.debug("Set  abcPropertiesCond: " + abcPropertiesCond);
	}
	/**
	 * Sets the {@code allNotNullCondTargets} property to {@code ArrayList<Target>} argument.
	 * 
	 * @param allNotNullCondTargets
	 */
	public void setAllNotNullCondTargets(ArrayList<Target> allNotNullCondTargets) {
		this.allNotNullCondTargets = allNotNullCondTargets;
		log.debug("Set  allNotNullCondTargets: " + allNotNullCondTargets);
	}
	/**
	 * Sets the {@code clickedConditionTarget} property to {@code Target} argument.
	 * 
	 * @param clickedConditionTarget
	 */
	public void setClickedConditionTarget(Target clickedConditionTarget) {
		this.clickedConditionTarget = clickedConditionTarget;
		log.debug("Set  clickedConditionTarget: " + clickedConditionTarget);
	}
	/**
	 * Sets the {@code abcPropertiesObl} property to {@code boolean} argument.
	 * 
	 * @param abcPropertiesObl
	 */
	public void setAbcPropertiesObl(boolean abcPropertiesObl) {
		this.abcPropertiesObl = abcPropertiesObl;
		log.debug("Set  abcPropertiesObl: " + abcPropertiesObl);
	}
	/**
	 * Sets the {@code abcPropertiesAuth} property to {@code boolean} argument.
	 * 
	 * @param abcPropertiesAuth
	 */
	public void setAbcPropertiesAuth(boolean abcPropertiesAuth) {
		this.abcPropertiesAuth = abcPropertiesAuth;
		log.debug("Set  abcPropertiesAuth: " + abcPropertiesAuth);
	}
	/**
	 * Sets the {@code abcProperties} property to {@code String} argument.
	 * 
	 * @param abcProperties
	 */
	public void setAbcProperties(String abcProperties) {
		this.abcProperties = abcProperties;
		log.debug("Set  abcProperties: " + abcProperties);
	}
	/**
	 * Sets the {@code subjListTarg} property to {@code List<Object[]>} argument.
	 * 
	 * @param subjListTarg
	 */
	public void setSubjListTarg(List<Object[]> subjListTarg) {
		this.subjListTarg = subjListTarg;
		log.debug("Set  subjListTarg: " + subjListTarg);
	}
	/**
	 * Sets the {@code resListTarg} property to {@code List<Object[]>} argument.
	 * 
	 * @param resListTarg
	 */
	public void setResListTarg(List<Object[]> resListTarg) {
		this.resListTarg = resListTarg;
		log.debug("Set  resListTarg: " + resListTarg);
	}
	/**
	 * Sets the {@code actListTarg} property to {@code List<Object[]>} argument.
	 * 
	 * @param actListTarg
	 */
	public void setActListTarg(List<Object[]> actListTarg) {
		this.actListTarg = actListTarg;
		log.debug("Set  actListTarg: " + actListTarg);
	}
	/**
	 * Sets the {@code envListTarg} property to {@code List<Object[]>} argument.
	 * 
	 * @param envListTarg
	 */
	public void setEnvListTarg(List<Object[]> envListTarg) {
		this.envListTarg = envListTarg;
		log.debug("Set  envListTarg: " + envListTarg);
	}
	/**
	 * Sets the {@code allEnvAttributes} property to {@code ArrayList<EnvironmentAttribute>} argument.
	 * 
	 * @param allEnvAttributes
	 */
	public void setAllEnvAttributes(
			ArrayList<EnvironmentAttribute> allEnvAttributes) {
		this.allEnvAttributes = allEnvAttributes;
		log.debug("Set  allEnvAttributes: " + allEnvAttributes);
	}
	
	
	
	/*****************************************************************************************************/
	
	/**
	 * Print or render the pre and onGoing ABC property depending upon which combo box is checked
	 */
	public void print() {
		if (this.abcProperties.equals("auth")) {
			this.abcPropertiesAuth = true;
			this.abcPropertiesObl = false;
			this.abcPropertiesCond = false;
			log.info("Rendering Pre and Ongoing Authorization");
			this.preABC = " Pre Authorization";
			this.onGoingABC = " On-Going Authorization";
			this.propertyABC = "Authorization";
		} else if (this.abcProperties.equals("obl")) {
			this.abcPropertiesAuth = false;
			this.abcPropertiesObl = true;
			this.abcPropertiesCond = false;
			log.info("Rendering Pre and Ongoing Obligation");
			this.preABC = " Pre Obligation";
			this.onGoingABC = " On-Going Obligation";
			this.propertyABC = "Obligation";
		} else {
			this.abcPropertiesAuth = false;
			this.abcPropertiesObl = false;
			this.abcPropertiesCond = true;
			log.info("Rendering Pre and Ongoing Condition");
			this.preABC = " Pre Condition";
			this.onGoingABC = " On-Going Condition";
			this.propertyABC = "Condition";
		}
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
			}
		}
		log.info("Funtion Ids Populated Successfully");
	}
	
	/**
	 * Showing the success message on the successful creation and insertion of
	 * the Condition into the database.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Environment Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Condition Successfully"));

			this.setOperationFail(true);
		}
	}
	
	/*public void addAtrributeDesignator() {
		System.out.println("addDesignator");

	}*/

	/**
	 * Saving the created instance of {@code AttributeDesignator}, and adding it
	 * into the Condition Tree. It hides enables the Main addCondition Dialog by
	 * closing the addDesginator Dialog box.
	 */
	public void saveDesignator() {
		Expression testDesignator = new AttributeDesignator(
				this.attributeDesignatorId, this.designatorId,
				this.designatorType);
		testDesignator.setApply(apply);
		RequestContext context = RequestContext.getCurrentInstance();
		TreeNode temp = new DefaultTreeNode("Designator: " + this.designatorId,
				this.selectedNode);
		newNode.add(temp);
		// testDAO.createExpression(testDesignator);
		createdExpression.add(testDesignator);

		designatorId = null;
		designatorType = null;
		attributeDesignatorId = null;

		context.showMessageInDialog(new FacesMessage(" Successful Execution",
				"Designator Added to Condition Successfully"));
		log.info("Closing dialog.");

		context.execute("addDesignatorDialog.hide()");
	}
	
	/**
	 * Canceling the created Designator, and reactivating the addCondition main
	 * dialog, by closing the addDesignator Dialog box.
	 */
	public void cancelDesignator() {
		RequestContext context = RequestContext.getCurrentInstance();
		designatorId = null;
		designatorType = null;
		attributeDesignatorId = null;
		log.info("Adding designator was cancelled.");
		context.execute("addDesignatorDialog.hide()");
	}
	
	
	/*public void addValue() {
		System.out.println("Adding Value");
	}*/

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
		createdExpression.add(testValue);
		attributeValue = null;
		valueType = null;

		context.showMessageInDialog(new FacesMessage(" Successful Execution",
				"Attribute Value Added to Condition Successfully"));
		log.info("Closing dialog.");

		context.execute("addValueDialog.hide()");
	}
	
	/**
	 * Canceling the created value and reactivating the main addCondition page
	 * by closing the addValue Dialog box.
	 */
	public void cancelValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		attributeValue = null;
		valueType = null;
		log.info("Closing the Created Value");
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


		if (this.condDescription == null) {
			// log.info("Description cannot be empty.");


			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Description cannot be empty."));
			log.info("Saving Condition was unsuccessful");
			return null;
		}

		if (this.apply == null) {
			// log.info("Description cannot be empty.");

			System.out.println("apply null");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Apply cannot be empty."));
			log.info("Saving Condition was unsuccessful");
			return null;
		}

		System.out.println("Saving Condition: " + condDescription);
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
	 * Setting the selected node to the {@code selectedNode} variable.
	 * 
	 * @param event
	 *            the selected Node
	 */
	public void onNodeSelect(NodeSelectEvent event) {
		this.selectedNode = event.getTreeNode();
		log.info("Node Selected Successfully");
	}

	/*public void addApply() {

		System.out.println("addApply");

	}*/

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
			testApply.setApply(apply);
			apply = testApply;
		}

		TreeNode temp = new DefaultTreeNode("Apply: " + this.applyDesc,
				this.selectedNode);
		newNode.add(temp);
		number.add(selectedNumber);
		createdApply.add(apply);
		System.out.println("Leaving Apply");
		applyDesc = null;
		applyFuncId = null;
		applyType = null;
		selectedNumber = null;
		System.out.println(selectedNumber);

		context.showMessageInDialog(new FacesMessage(" Successful Execution",
				"Apply Added to Condition Successfully"));
		log.info("Apply Added to Condition Successfully.");

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
		log.info("Saving Ally Cancelled");
		context.execute("addApplyDialog.hide()");
	}
	
	/**
	 * Function used to initialize all member variables It is called whenever
	 * there is a need to reinitialize the data members.
	 */
	public void initialize() {
		newNode = new ArrayList<TreeNode>();
		createdApply = new ArrayList<Apply>();
		createdExpression = new ArrayList<Expression>();

		condDescription = null;

		cond = new Condition();
		rootApply = new Apply();
		apply = null;

		applyFuncId = "String";
		applyDesc = null;
		applyType = null;

		designatorId = null;
		designatorType = null;
		attributeDesignatorId = null;

		attributeValue = null;
		valueType = null;

		root = new DefaultTreeNode("Root", null);
		TreeNode node0 = new DefaultTreeNode("Condition", root);
		selectedNode = node0;

		arguments = Arrays.asList("1", "2");
		number = new ArrayList<String>();
		selectedNumber = null;

	}
	
	/**
	 * Opens the {@code  /Policy Creation/Condition/AddCondition.xhtml} page for
	 * creating a new {@code Condition} instance.
	 */
	public String addCondition() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 550);
		options.put("width", 1200);
		options.put("contentHeight", 500);
		options.put("contentWidth", 1150);
		options.put("modal", true);
		log.info("Opening /Policy Creation/UCON Policy/AddCondition in a dialog.");
		root = new DefaultTreeNode("Root", null);
		TreeNode node0 = new DefaultTreeNode("Obligation", root);
		selectedNode = node0;
		context.openDialog("/Policy Creation/UCON Policy/AddCondition",
				options, null);

		return null;

		/*
		 * System.out.println("Here"); return
		 * "/Policy Creation/Condition/AddCondition?faces-redirect=true";
		 */
	}

	/**
	 * Deletes an instance of {@code Condition} stored in
	 * {@code selectedCondition} property
	 */
	public void deleteCondition() {
		log.info("Condition Deleted Successfully");
		conditionDao.deleteCondition(selectedCondition);
	}
	
	/**
	 * As soon as the on or onGoingUpdate checkbox is checked
	 * or unchecked, {@code onGoingReqOrUpdate} change accordingly
	 */
	public void changeOnGoingState() {
		if (isOnGoingUpdateCheckBox() || on) {
			setOnGoingReqOrUpdate(true);
			log.info("on or onGoingUpdate checkbox checked");
		} else{
			setOnGoingReqOrUpdate(false);
			log.info("on or onGoingUpdate checkbox unchecked");
		}
	}
	
	/*public void onClickPreUpdate() {
		System.out.println("Function Called");
	}*/

	/*public void printIteratorValues(Iterator<PreUpdate> it) {
		while (it.hasNext()) {
			PreUpdate temp = it.next();
			System.out.println(temp.getPreAttrId() + "," + temp.getPreValue());
		}
	}*/

	/**
	 * Updating Added Attribute Assignments List Action Listener of Add Button
	 * in PreUpdate gui
	 */
	public void preUpdateActionListener() {
		Iterator<AttributeAssignment> it = this.preValues.iterator();
		int indexToBeUpdated = 0;
		while (it.hasNext()) {
			AttributeAssignment temp = it.next();
			if (temp != null && temp.getAttributeId() != null) {
				if (temp.getAttributeId().equals(this.preAttrId)
						&& this.preValue.length() > 0) {
					this.preValues.set(indexToBeUpdated,
							new AttributeAssignment(this.preAttrId,
									this.preValue, ""));
					break;
				}
			}
			indexToBeUpdated++;
		}
		if (indexToBeUpdated == this.preValues.size()
				&& this.preValue.length() > 0) {
			this.preValues.add(new AttributeAssignment(this.preAttrId,
					this.preValue, ""));
			this.preValues.get(indexToBeUpdated).setDataType(
					"http://www.w3.org/2001/XMLSchema#string");

		}
		this.preValue = "";
		log.info("Pre Update is Added into the PreUpdate Data Table");
	}

	/**
	 * It will remove the entry of Attribute PreUpdate row from the PreUpdate
	 * Data Table
	 */
	public void deleteRowOfPre() {
		for (int u = 0; u < this.preValues.size(); u++) {
			if (this.selectedPreUpdate.getAttributeId().equals(
					this.preValues.get(u).getAttributeId())) {
				this.preValues.remove(u);
			}
		}
		log.info("PreUpdate Row deleted Successfully");
	}

	/**
	 * Updating Added Attribute Assignments List Action Listener of Add Button
	 * in OnGoingUpdate gui
	 */
	public void onGoingUpdateActionListener() {
		Iterator<AttributeAssignment> it = this.onGoingValues.iterator();
		int indexToBeUpdated = 0;
		while (it.hasNext()) {
			AttributeAssignment temp = it.next();
			if (temp != null && temp.getAttributeId() != null
					&& this.onGoingValue.length() > 0) {
				if (temp.getAttributeId().equals(this.onGoingAttrId)) {
					this.onGoingValues.set(indexToBeUpdated,
							new AttributeAssignment(this.onGoingAttrId,
									this.onGoingValue, ""));

					break;
				}
			}
			indexToBeUpdated++;
		}
		if (indexToBeUpdated == this.onGoingValues.size()
				&& this.onGoingValue.length() > 0) {
			this.onGoingValues.add(new AttributeAssignment(this.onGoingAttrId,
					this.onGoingValue, ""));
			this.onGoingValues.get(indexToBeUpdated).setDataType(
					"http://www.w3.org/2001/XMLSchema#string");
		}
		this.onGoingValue = "";
		this.onGoingTime = "";
		log.info("OnGoing Update is Added into the onGoingUpdate Data Table");
	}

	/**
	 * Updating Added Attribute Assignments List Action Listener of Add Button
	 * in PostUpdate gui
	 */
	public void postUpdateActionListener() {
		Iterator<AttributeAssignment> it = this.postValues.iterator();
		int indexToBeUpdated = 0;
		while (it.hasNext()) {
			AttributeAssignment temp = it.next();
			if (temp != null && temp.getAttributeId() != null
					&& this.postValue.length() > 0) {
				if (temp.getAttributeId().equals(this.postAttrId)) {
					this.postValues.set(indexToBeUpdated,
							new AttributeAssignment(this.postAttrId,
									this.postValue, ""));
					break;
				}
			}
			indexToBeUpdated++;
		}
		if (indexToBeUpdated == this.postValues.size()
				&& this.postValue.length() > 0) {
			this.postValues.add(new AttributeAssignment(this.postAttrId,
					this.postValue, ""));
			this.postValues.get(indexToBeUpdated).setDataType(
					"http://www.w3.org/2001/XMLSchema#string");
		}
		this.postValue = "";
		log.info("Post Update is Added into the postUpdate Data Table");
	}

	/**
	 * It will remove the entry of Attribute PreUpdate row from the PostUpdate
	 * Data Table
	 */
	public void deleteRowOfPost() {
		for (int u = 0; u < this.postValues.size(); u++) {
			if (this.selectedPostUpdate.getAttributeId().equals(
					this.postValues.get(u).getAttributeId())) {
				this.postValues.remove(u);
			}
		}
		log.info("PostUpdate Row deleted Successfully");
	}

	/**
	 * It will remove the entry of Attribute PreUpdate row from the PostUpdate
	 * Data Table
	 */
	public void deleteRowOfOnGoing() {
		for (int u = 0; u < this.onGoingValues.size(); u++) {
			if (this.selectedOnGoingUpdate.getAttributeId().equals(
					this.onGoingValues.get(u).getAttributeId())) {
				this.onGoingValues.remove(u);
			}
		}
		log.info("OnGoingUpdate Row deleted Successfully");
	}

	/**
	 * Saving the created UCON {@code Policy} in Database
	 * and hiding add Dialog
	 */
	public void savePolicy() {
		ArrayList<Obligations> obligations = new ArrayList<Obligations>();
		ObligationsDAO obligationDao = new ObligationsDAO();
		AttributeAssignmentDAO aaDao = new AttributeAssignmentDAO();

		policyName += "urn";
		if (pre)
			policyName += ":pre";
		

		if (on) {
			policyName += ":on";
			ArrayList<AttributeAssignment> attAssignments = new ArrayList<AttributeAssignment>();

			AttributeAssignment attAssign = aaDao.createAttributeAssignment(
					"request_interval", reqInterval, "");
			
			attAssign.setDataType("http://www.w3.org/2001/XMLSchema#string");
			attAssignments.add(attAssign);
			Obligations obligation = obligationDao.createObligations(
					"urn:xacml:ucon:on", "", "Permit", new HashSet(
							attAssignments));
			obligations.add(obligation);
		}
		if (isPreUpdateCheckBox()) {
			policyName += ":1";
			Iterator<AttributeAssignment> iterator = preValues.iterator();
			ArrayList<AttributeAssignment> attAssignments = new ArrayList<AttributeAssignment>();
			while (iterator.hasNext()) {
				AttributeAssignment preUpdate = (AttributeAssignment) iterator
						.next();
				AttributeAssignment attAssign = aaDao
						.createAttributeAssignment(
								"update_" + preUpdate.getAttributeId(),
								preUpdate.getAttributeValue(), "");
				attAssign
						.setDataType("http://www.w3.org/2001/XMLSchema#string");
				attAssignments.add(attAssign);

			}
			Obligations obligation = obligationDao.createObligations(
					"urn:xacml:ucon:preUpdate", "",
					EffectType.PERMIT.toString(), new HashSet(attAssignments));
			obligations.add(obligation);

		}
		if (isPostUpdateCheckBox()) {

			policyName += ":3";
			Iterator<AttributeAssignment> iterator = postValues.iterator();
			ArrayList<AttributeAssignment> attAssignments = new ArrayList<AttributeAssignment>();
			while (iterator.hasNext()) {
				AttributeAssignment postUpdate = (AttributeAssignment) iterator
						.next();
				AttributeAssignment attAssign = aaDao
						.createAttributeAssignment(
								"update_" + postUpdate.getAttributeId(),
								postUpdate.getAttributeValue(), "");
				attAssign
						.setDataType("http://www.w3.org/2001/XMLSchema#string");
				attAssignments.add(attAssign);

			}
			Obligations obligation = obligationDao.createObligations(
					"urn:xacml:ucon:postUpdate", "",
					EffectType.DENY.toString(), new HashSet(attAssignments));
			obligations.add(obligation);

		}
		if (isOnGoingUpdateCheckBox()) {
			policyName += ":2";
			Iterator<AttributeAssignment> iterator = onGoingValues.iterator();
			ArrayList<AttributeAssignment> attAssignments = new ArrayList<AttributeAssignment>();
			while (iterator.hasNext()) {
				AttributeAssignment onGoingUpdate = (AttributeAssignment) iterator
						.next();
				AttributeAssignment attAssign = aaDao
						.createAttributeAssignment(
								"update_" + onGoingUpdate.getAttributeId(),
								onGoingUpdate.getAttributeValue(), "");
				attAssign
						.setDataType("http://www.w3.org/2001/XMLSchema#string");
				attAssignments.add(attAssign);

			}
			Obligations obligation = obligationDao.createObligations(
					"urn:xacml:ucon:onGoingUpdate", "",
					EffectType.PERMIT.toString(), new HashSet(attAssignments));
			obligations.add(obligation);

		}

		RuleDAO ruleDao = new RuleDAO();
		ArrayList<Rule> ruleList = new ArrayList<Rule>();
		if (this.abcPropertiesAuth) {
			Rule rule = ruleDao.createRule(null, this.policyName,
					this.appliedEffect);
			ruleList.add(rule);
			policyDao.createPolicy(this.policyName, this.appliedAlgo,
					this.clickedTarget, this.policyDescription, new HashSet(
							ruleList), new HashSet(obligations));
		} else if (this.abcPropertiesCond) {
			Rule rule = ruleDao.createRule(null, this.policyName,
					this.appliedEffect);
			ruleList.add(rule);
			policyDao.createPolicy(this.policyName, this.appliedAlgo,
					this.clickedConditionTarget, this.policyDescription,
					new HashSet(ruleList), new HashSet(obligations));
		} else {
			Rule rule = ruleDao.createRule(this.selectedCondition,
					this.policyName, this.appliedEffect);
			ruleList.add(rule);
			policyDao.createPolicy(this.policyName, this.appliedAlgo,
					this.clickedOblTarget, this.policyDescription, new HashSet(
							ruleList), new HashSet(obligations));
		}
		policyName = null;
		clickedTarget = null;
		policyDescription = null;
		this.setOpertionFail(false);
		this.showAddMessage();
		RequestContext context = RequestContext.getCurrentInstance();
		context.closeDialog(this);
		log.info("Policy saved Successfully");
	}
	
	/**
	 * Function used to initialize all member variables It is called whenever
	 * there is a need to reinitialize the data members.
	 */
	public UconPolicyWizardController() {
		this.ruleEffects.add("PERMIT");
		this.ruleEffects.add("DENY");
		this.appliedEffect = "";
		this.preABC = " Pre Authorization";
		this.onGoingABC = " On-Going Authorization";
		this.propertyABC = "Authorization";
		this.abcPropertiesAuth = true;
		this.preUpdateCheckBox = false;
		this.onGoingUpdateCheckBox = false;
		this.postUpdateCheckBox = false;
		this.preAttrId = "";
		this.preValue = "";
		this.preValues = new ArrayList<AttributeAssignment>();
		this.onGoingAttrId = "";
		this.onGoingValue = "";
		this.onGoingValues = new ArrayList<AttributeAssignment>();
		this.postAttrId = "";
		this.postValue = "";
		this.postValues = new ArrayList<AttributeAssignment>();
		this.dataTypes = new ArrayList<String>();
		this.dataTypes.add("String");
		this.dataTypes.add("Integer");
		this.dataTypes.add("TimeDate");

		this.selectedPreUpdate = null;
		this.selectedOnGoingUpdate = null;
		this.selectedPostUpdate = null;

		this.attrIds = new ArrayList<String>();
		this.onGoingAttrIds = new ArrayList<String>();
		this.postAttrIds = new ArrayList<String>();

		this.onGoingTimes = new ArrayList<String>();
		log.info("Initialize all member variables");
	}
	
	/**
	 * Show Message to user that updated Successfully
	 */
	public void showUpdateMessage() {

		if (!isOpertionFail()) {
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Updated Successfully"));

			this.setOpertionFail(true);
			log.info("Updated Successfully");
		}

	}

	/**
	 * Show Message to user that created Successfully
	 */
	public void showAddMessages() {

		if (!isOpertionFail()) {
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Created Successfully"));
			
			this.setOpertionFail(true);
			log.info("Created Successfully");
		}

	}
	
	/**
	 * Save Updated {@code Action} in Selected {@code Target}
	 */
	public void saveUpdatedTargetAction() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (clickedTarget != null) {
			actListTarg = addForActionMatch();
			if (actListTarg == null)
				actListTarg = new ArrayList<Object[]>();

			List<ActionMatch> actionMatch = dao.createActionMatch(actListTarg,
					this.isMustBePresent());
			if (actionMatch == null)
				actionMatch = new ArrayList<ActionMatch>();

			if (this.selectedMatchId != null && matchIds != null) {
				if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
					System.out.println("MId Not NULL");
					System.out.println(this.selectedMatchId);
					this.setOpertionFail(false);
					dao.updateTargetActions(clickedTarget.getPkTarget(),
							actionMatch);
					context.closeDialog(this);
					this.selectedSubject = null;
					this.selectedResource = null;
					this.selectedAction = null;
					this.selectedEnvironment = null;
					this.selectedActionAttributes = null;
					this.selectedMatchId = null;
					this.selectedResourceAttribute = null;
					this.selectedSubjectAttributes = null;
					this.selectedEnvironmentAttribute = null;
					this.selectedActValue = null;
					// this.selectedActAttValues.clear();
					this.matchIds = null;
					this.mustBePresent = false;
				} else
					context.execute("noMatchIdDialoga.show()");
			} else {
				System.out.println("MId NULL");
				context.execute("noMatchIdDialoga.show()");
			}
		}
		log.info("Action Updated Successfully");
	}

	/**
	 * Save Updated {@code Environment} in Selected {@code Target}
	 */
	public void saveUpdatedTargetEnvironment() {
		RequestContext context = RequestContext.getCurrentInstance();
		List<EnvironmentMatch> environmentMatch;
		System.out.println("Look I am Callled");
		if (clickedTarget == null) {
			setClickedTarget(dao.createTarget("", "No Authorization",
					new ArrayList<SubjectMatch>(),
					new ArrayList<ActionMatch>(),
					new ArrayList<ResourceMatch>(),
					new ArrayList<EnvironmentMatch>()));
			addEnvToSelection();// Called to Update Environment Values List
			envListTarg = addForEnvironmentMatch();
			if (envListTarg == null) {
				envListTarg = new ArrayList<Object[]>();
				System.out.println("Here The List Was Empty");
			}
			if (envListTarg.isEmpty())
				System.out.println("Empty Was Here");
			environmentMatch = dao.createEnvironmentMatch(envListTarg,
					this.isMustBePresent());
			if (environmentMatch == null) {
				System.out.println("No Here it Was Empty");
				environmentMatch = new ArrayList<EnvironmentMatch>();
			}
			if (this.selectedMatchId != null && matchIds != null) {
				if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
					this.setOpertionFail(false);
					System.out.println(this.selectedMatchId);
					dao.updateTargetEnvironments(clickedTarget.getPkTarget(),
							environmentMatch);
					context.closeDialog(this);
					this.selectedSubject = null;
					this.selectedResource = null;
					this.selectedAction = null;
					this.selectedEnvironment = null;
					this.selectedActionAttributes = null;
					this.selectedMatchId = null;
					this.selectedResourceAttribute = null;
					this.selectedSubjectAttributes = null;
					this.selectedEnvironmentAttribute = null;
					this.selectedEnvValue = null;
					// this.selectedEnvAttValues.clear();
					this.matchIds = null;
					this.mustBePresent = false;

				} else
					context.execute("noMatchIdDialoge.show()");
			} else {
				System.out.println("MId NULL");
				context.execute("noMatchIdDialoge.show()");
			}
		} else if (clickedTarget != null) {
			envListTarg = addForEnvironmentMatch();
			if (envListTarg == null)
				envListTarg = new ArrayList<Object[]>();

			environmentMatch = dao.createEnvironmentMatch(envListTarg,
					this.isMustBePresent());
			if (environmentMatch == null)
				environmentMatch = new ArrayList<EnvironmentMatch>();
			if (this.selectedMatchId != null && matchIds != null) {
				if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
					this.setOpertionFail(false);
					System.out.println(this.selectedMatchId);
					dao.updateTargetEnvironments(clickedTarget.getPkTarget(),
							environmentMatch);
					context.closeDialog(this);
					this.selectedSubject = null;
					this.selectedResource = null;
					this.selectedAction = null;
					this.selectedEnvironment = null;
					this.selectedActionAttributes = null;
					this.selectedMatchId = null;
					this.selectedResourceAttribute = null;
					this.selectedSubjectAttributes = null;
					this.selectedEnvironmentAttribute = null;
					this.selectedEnvValue = null;
					// this.selectedEnvAttValues.clear();
					this.matchIds = null;
					this.mustBePresent = false;
				} else
					context.execute("noMatchIdDialoge.show()");
			} else {
				System.out.println("MId NULL");
				context.execute("noMatchIdDialoge.show()");
			}

		}
		log.info("Environment Updated Successfully");
	}

	/**
	 * Delete the Selected {@code Action} from the Selected {@code Target}
	 */
	public void deleteAction() {
		dao.deleteAction(clickedTarget.getPkTarget(), selectedActions,
				this.addedTargetAction);
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		log.info("Action Deleted Successfully");
	}

	/**
	 * Delete the Selected {@code Environment} from the Selected {@code Target}
	 */
	public void deleteEnvironment() {
		dao.deleteEnvironment(clickedTarget.getPkTarget(),
				selectedEnvironments, this.addedTargetEnvironment);
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		log.info("Environment Deleted Successfully");
	}

	/**
	 * Open the Add Environment dialog from /Policy Creation/UCON Policy/AddNewTargetEnvironmentDialog
	 */
	public void updateTargetEnvironmentByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 395);
		options.put("width", 1100);
		options.put("contentHeight", 380);
		options.put("contentWidth", 1050);
		options.put("modal", true);

		context.openDialog(
				"/Policy Creation/UCON Policy/AddNewTargetEnvironmentDialog",
				options, null);
		log.info("Opening Dailog /Policy Creation/UCON Policy/AddNewTargetEnvironmentDialog");
	}
	
	/**
	 * Deletes the selected Resource
	 */
	public void deleteResource() {
		dao.deleteResource(clickedTarget.getPkTarget(), this.selectedResources,
				this.addedTargetResource);
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		log.info("Resource Deleted Successfully");
	}
	
	/**
	 * Cancel any changes made in any Update Target Dialog
	 */
	public void cancelUpdatedTarget() {
		RequestContext context = RequestContext.getCurrentInstance();
		context.closeDialog(this);
		this.selectedSubject = null;
		this.selectedResource = null;
		this.selectedAction = null;
		this.selectedEnvironment = null;
		this.selectedActionAttributes = null;
		this.selectedMatchId = null;
		this.selectedResourceAttribute = null;
		this.selectedSubjectAttributes = null;
		this.selectedEnvironmentAttribute = null;
		this.selectedSubValue = null;
		this.selectedResValue = null;
		this.selectedActValue = null;
		this.selectedEnvValue = null;
		this.mustBePresent = false;
		log.info("Target Update is Cancelled");
	}

	/**
	 * Save Updated {@code Subject} in Selected {@code Target}
	 */
	public void saveUpdatedTargetSubject() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (clickedTarget != null) {
			subjListTarg = addForSubjectMatch();
			if (subjListTarg == null)
				subjListTarg = new ArrayList<Object[]>();

		}
		System.out.println("Size Here is : " + subjListTarg.size());
		System.out.println("In Subject is :" + this.selectedMatchId);

		List<SubjectMatch> subjectMatch = dao.createSubjectMatch(subjListTarg,
				this.isMustBePresent());
		if (subjectMatch == null) {
			subjectMatch = new ArrayList<SubjectMatch>();
		}
		for (int y = 0; y < subjectMatch.size(); y++) {
			SubjectMatch sMatch = (SubjectMatch) subjectMatch.get(y);
			// Set<Subjects> s = sMatch.getSubjects();
			SubAttrValues vals = sMatch.getSubAttrValues();
			String matchId = sMatch.getMatchId();
			System.out.println("Added Tag value : " + vals.getPkSubAttrVal()
					+ " mIds : " + matchId + " " + y);
		}
		System.out.println("After Loop Before Condition : "
				+ this.selectedMatchId);
		if (this.selectedMatchId != null && matchIds != null) {
			if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
				System.out.println("MId Not NULL");
				System.out.println(this.selectedMatchId);
				this.setOpertionFail(false);
				dao.updateTargetSubjects(clickedTarget.getPkTarget(),
						subjectMatch);
				context.closeDialog(this);
				this.selectedSubject = null;
				this.selectedResource = null;
				this.selectedAction = null;
				this.selectedEnvironment = null;
				this.selectedActionAttributes = null;
				this.selectedMatchId = null;
				this.selectedResourceAttribute = null;
				this.selectedSubjectAttributes = null;
				this.selectedEnvironmentAttribute = null;
				// this.selectedSubAttValues.clear();
				this.selectedSubValue = null;
				this.matchIds = null;
				this.mustBePresent = false;
			} else
				context.execute("noMatchIdDialogs.show()");
		} else {
			System.out.println("MId NULL");
			context.execute("noMatchIdDialogs.show()");
		}
		log.info("Subject Updated Successfully");
	}

	/**
	 * Delete the Selected {@code Subject} from the Selected {@code Target}
	 */
	public void deleteSubject() {
		if (this.addedTargetSubject != null) {
			dao.deleteSubject(clickedTarget.getPkTarget(), selectedSubjects,
					this.addedTargetSubject);
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
			log.info("Subject Deleted Successfully");
		}

		else
			log.info("Subject Deleted unSuccessfully");
	}

	/**
	 * Open Dialog /Policy Creation/UCON Policy/AddNewTargetResourcesDialog
	 * to Add {@code Resource} in Selected {@code Target}
	 */
	public void updateTargetResourceByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 395);
		options.put("width", 1100);
		options.put("contentHeight", 380);
		options.put("contentWidth", 1050);
		options.put("modal", true);

		context.openDialog(
				"/Policy Creation/UCON Policy/AddNewTargetResourcesDialog",
				options, null);
		log.info("Opening Dialog /Policy Creation/UCON Policy/AddNewTargetResourcesDialog");
	}

	/**
	 * Opens Dialog /Policy Creation/UCON Policy/AddNewTargetActionDialog 
	 * to add {@code Action} in Selected {@code Target}
	 */
	public void updateTargetActionByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 395);
		options.put("width", 1100);
		options.put("contentHeight", 380);
		options.put("contentWidth", 1050);
		options.put("modal", true);

		context.openDialog(
				"/Policy Creation/UCON Policy/AddNewTargetActionDialog",
				options, null);
		log.info("Opening Dialog /Policy Creation/UCON Policy/AddNewTargetActionDialog");

	}

	/**
	 * Save Updated {@code Resource} in Selected {@code Target}
	 */
	public void saveUpdatedTargetResource() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (clickedTarget != null) {

			resListTarg = addForResourceMatch();
			if (resListTarg == null)
				resListTarg = new ArrayList<Object[]>();
		}
		List<ResourceMatch> resourceMatch = dao.createResourceMatch(
				resListTarg, this.isMustBePresent());
		if (resourceMatch == null)
			resourceMatch = new ArrayList<ResourceMatch>();
		if (this.selectedMatchId != null && matchIds != null) {
			if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
				System.out.println("MId Not NULL");
				System.out.println(this.selectedMatchId);
				this.setOpertionFail(false);
				dao.updateTargetResources(clickedTarget.getPkTarget(),
						resourceMatch);
				context.closeDialog(this);
				this.selectedSubject = null;
				this.selectedResource = null;
				this.selectedAction = null;
				this.selectedEnvironment = null;
				this.selectedActionAttributes = null;
				this.selectedMatchId = null;
				this.selectedResourceAttribute = null;
				this.selectedSubjectAttributes = null;
				this.selectedEnvironmentAttribute = null;
				this.selectedResValue = null;
				// this.selectedResAttValues.clear();
				this.matchIds = null;
				this.mustBePresent = false;
			} else
				context.execute("noMatchIdDialogr.show()");

		} else {
			System.out.println("MId NULL");
			context.execute("noMatchIdDialogr.show()");
		}
		log.info("Resource Updated Successfully");
	}
	
	/**
	 * Save Updated {@code Target} {@code Description}
	 * and hide Target description dialog
	 */
	public void saveUpdatedTargetDescription() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (clickedTarget != null) {
			dao.updateTarget(clickedTarget.getPkTarget(), updatedTargetId,
					updatedDescription);
			this.setOpertionFail(false);
		}
		context.closeDialog(this);
		log.info("Target Description Updated Succcessfully");
	}

	/**
	 * Cancel the changes made in Target Description dialog
	 */
	public void cancelUpdatedTargetDescription() {
		RequestContext context = RequestContext.getCurrentInstance();
		context.closeDialog(this);
		log.info("Update Target Description Cancelled");
	}

	/**
	 * Opens Dialog /Policy Creation/UCON Policy/AddNewTargetSubjectDialog 
	 * to add {@code Subject} in Selected {@code Target}
	 */
	public void updateTargetSubjectByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 395);
		options.put("width", 1100);
		options.put("contentHeight", 380);
		options.put("contentWidth", 1050);
		options.put("modal", true);
		context.openDialog(
				"/Policy Creation/UCON Policy/AddNewTargetSubjectDialog.xhtml",
				options, null);
		log.info("Opening Dialog /Policy Creation/UCON Policy/AddNewTargetSubjectDialog");
	}
	
	/**
	 * Opens Dialog /Policy Creation/UCON Policy/Update/UpdateTargetDialog
	 * to update Target 
	 */
	public void updateTargetByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 365);
		options.put("contentHeight", 230);
		options.put("contentWidth", 350);
		options.put("modal", true);

		context.openDialog(
				"/Policy Creation/UCON Policy/Update/UpdateTargetDialog",
				options, null);
		log.info("Opening Dialog /Policy Creation/UCON Policy/Update/UpdateTargetDialog");
	}

	/**
	 * Redirect to the page to update {@code Target}
	 * @return Redirecting to the Update Target Page
	 */
	public String updateTarget() {
		return "updateExistingTarget?faces-redirect=true";
	}
	
	/**
	 * Add {@code Subject} for the Selected {@code Target} 
	 * in the Subject Data Table
	 */
	public void addSubToSelection() {
		selectedSubAttrValues = new ArrayList<SubAttrValues>();
		selectedSubMatchIds = new ArrayList<String>();
		if (clickedTarget != null) {
			List<Subjects> subjects = dao.populateTargetSubjects(clickedTarget
					.getPkTarget());
			Iterator<Subjects> subjIter = subjects.iterator();
			int k = 0;
			while (subjIter.hasNext()) {
				Subjects sub = (Subjects) subjIter.next();
				SubAttrValues subValues = dao
						.getRequiredSubjectAttributeValue(sub);
				String subMatchId = dao.getMatchId(sub);
				selectedSubAttrValues.add(subValues);
				selectedSubMatchIds.add(subMatchId);
				k++;
			}
			this.selectedSubAttrValues.add(this.selectedSubValue);
			this.selectedSubMatchIds.add(this.selectedMatchId);
			log.info("Subject Added Successfully");
		}
	}

	/**
	 * Add {@code Resource} for the Selected {@code Target} 
	 * in the Resource Data Table
	 */
	public void addResToSelection() {
		if (selectedResource != null && selectedResourceAttribute != null
				&& selectedResValue != null && selectedMatchId != null) {
			selectedResAttrValues = new ArrayList<ResAttrValues>();
			selectedResMatchIds = new ArrayList<String>();
			if (clickedTarget != null) {

				List<Resources> resources = dao
						.populateTargetSubjectsResources(clickedTarget
								.getPkTarget());
				Iterator<Resources> resIter = resources.iterator();
				int k = 0;
				while (resIter.hasNext()) {
					Resources res = (Resources) resIter.next();
					ResAttrValues resValues = dao
							.getRequiredResourceAttributeValue(res);
					String resMatchId = dao.getMatchId(res);
					selectedResAttrValues.add(resValues);
					selectedResMatchIds.add(resMatchId);
					k++;
				}
				this.selectedResAttrValues.add(this.selectedResValue);
				this.selectedResMatchIds.add(this.selectedMatchId);
				log.info("Resource Added Successfully");
			}
			
		}
	}

	/**
	 * Add {@code Action} for the Selected {@code Target} 
	 * in the Action Data Table
	 */
	public void addActToSelection() {
		if (selectedAction != null && selectedActionAttributes != null
				&& selectedActValue != null && selectedMatchId != null) {
			selectedActAttrValues = new ArrayList<ActAttrValues>();
			selectedActMatchIds = new ArrayList<String>();
			if (clickedTarget != null) {
				List<Actions> actions = dao.populateTargetActions(clickedTarget
						.getPkTarget());
				Iterator<Actions> actIter = actions.iterator();
				int k = 0;
				while (actIter.hasNext()) {
					Actions acts = (Actions) actIter.next();
					ActAttrValues actValues = dao
							.getRequiredActionAttributeValue(acts);
					String actMatchId = dao.getMatchId(acts);
					selectedActAttrValues.add(actValues);
					selectedActMatchIds.add(actMatchId);
					k++;

				}
				this.selectedActAttrValues.add(selectedActValue);
				this.selectedActMatchIds.add(selectedMatchId);
				log.info("Action Added Successfully");
			}
		}
	}

	/**
	 * Add {@code Environment} for the Selected {@code Target} 
	 * in the Environment Data Table
	 */
	public void addEnvToSelection() {
		if (selectedEnvironment != null && selectedEnvironmentAttribute != null
				&& selectedEnvValue != null && selectedMatchId != null) {
			selectedEnvAttrValues = new ArrayList<EnvAttrValues>();
			selectedEnvMatchIds = new ArrayList<String>();
			if (clickedTarget != null) {
				List<Environments> environments = dao
						.populateTargetEnvironments(clickedTarget.getPkTarget());
				Iterator<Environments> envIter = environments.iterator();
				int k = 0;
				while (envIter.hasNext()) {
					Environments env = (Environments) envIter.next();
					EnvAttrValues envValues = dao
							.getRequiredEnvironmentAttributeValue(env);
					String envMatchId = dao.getMatchId(env);
					selectedEnvAttrValues.add(envValues);
					selectedEnvMatchIds.add(envMatchId);
					k++;
				}
				this.selectedEnvAttrValues.add(this.selectedEnvValue);
				this.selectedEnvMatchIds.add(this.selectedMatchId);
				log.info("Environment Added Successfully");
			}

		}
	}

	/**
	 * Load Match Ids into Memory
	 */
	public void populateMatchId() {
		XACMLConstants xacmlConsts = new XACMLConstants();
		ArrayList<String> allMIds = xacmlConsts.getMatchIds();
		matchIds = new ArrayList<String>();
		if (this.selectedSubValue != null) {
			String dataType = this.selectedSubjectAttributes.getDataType();
			System.out.println("Data Type is : " + dataType);
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					System.out.println("Match Id " + mId);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH))) {

							matchIds.add(mId);
						}
					}
				}
			}
			System.out.println("Match Ids Updated");
		} else if (this.selectedResValue != null) {
			String dataType = this.selectedResourceAttribute.getDataType();
			System.out.println("Data Type is : " + dataType);
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					System.out.println("Match Id " + mId);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
			System.out.println("Match Ids Updated");
		} else if (this.selectedActValue != null) {
			String dataType = this.selectedActionAttributes.getDataType();
			System.out.println("Data Type is : " + dataType);
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					System.out.println("Match Id " + mId);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
			System.out.println("Match Ids Updated");
		} else if (this.selectedEnvValue != null) {
			String dataType = this.selectedEnvironmentAttribute.getDataType();
			System.out.println("Data Type is : " + dataType);
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					System.out.println("Match Id " + mId);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
			System.out.println("Match Ids Updated");
		}
		log.info("Match Ids Loaded Successfully into the Memory");
	}
	
	/**
	 * Transform {@code Subject} data to the format required by the query for
	 * inserting data it does not change any variable that is required for other
	 * use
	 * 
	 * @return the data in the required format
	 */
	public List<Object[]> addForSubjectMatch() {
		List<Object[]> subMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedSubAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (SubAttrValues) selectedSubAttrValues.get(j);
			temp[1] = (String) selectedSubMatchIds.get(j);
			subMatch.add(temp);
		}
		log.info("Transform Subject Data into the required query formate Successfully");
		return subMatch;
	}

	/**
	 * Transform {@code Resource} data to the format required by the query for
	 * inserting data it does not change any variable that is required for other
	 * use
	 * 
	 * @return the data in the required format
	 */
	public List<Object[]> addForResourceMatch() {
		List<Object[]> resMatch = new ArrayList<Object[]>();

		for (int j = 0; j < selectedResAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (ResAttrValues) selectedResAttrValues.get(j);
			temp[1] = (String) selectedResMatchIds.get(j);
			resMatch.add(temp);
		}
		log.info("Transform Resource Data into the required query formate Successfully");
		return resMatch;
	}

	/**
	 * Transform {@code Action} data to the format required by the query for
	 * inserting data it does not change any variable that is required for other
	 * use
	 * 
	 * @return the data in the required format
	 */
	public List<Object[]> addForActionMatch() {
		List<Object[]> actMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedActAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (ActAttrValues) selectedActAttrValues.get(j);
			temp[1] = (String) selectedActMatchIds.get(j);
			actMatch.add(temp);
		}
		log.info("Transform Action Data into the required query formate Successfully");
		return actMatch;
	}

	/**
	 * Transform {@code Environment} data to the format required by the query for
	 * inserting data it does not change any variable that is required for other
	 * use
	 * 
	 * @return the data in the required format
	 */
	public List<Object[]> addForEnvironmentMatch() {
		List<Object[]> envMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedEnvAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (EnvAttrValues) selectedEnvAttrValues.get(j);
			temp[1] = (String) selectedEnvMatchIds.get(j);
			envMatch.add(temp);
		}
		log.info("Transform Environment Data into the required query formate Successfully");
		return envMatch;
	}
	
	/**
	 * Delete the Selected {@code Target}
	 */
	public void deleteTarget() {
		if (clickedTarget != null) {
			dao.deleteTarget(clickedTarget.getPkTarget());
			clickedTarget = null;
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
			log.info("Seleted Target Deleted Successfully");
		} else {
			RequestContext context = RequestContext.getCurrentInstance();
			context.execute("noTargetDialog.show()");
			log.info("Seleted Target Deleted unSuccessfully");
		}

	}
	
	/**
	 * Enables Add Button, in Target gui, when {@code Target} is selected
	 */
	public void onTargetSelected() {
		this.setAddbtn(false);
		log.info("Enable Add Button");
	}

	/**
	 * Disable Add Button, in Target gui, when {@code Target} is unselected
	 */
	void onTargetUnSelected() {
		this.setAddbtn(true);
		log.info("Disable Add Button");
	}

	/**
	 * Opens Add Subject Dialog UpdateTargetSubjectDialog 
	 * to be Added in {@code Target}
	 */
	public void addTargetSubjectByDialog() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 380);
		options.put("width", 1100);
		options.put("contentHeight", 380);
		options.put("contentWidth", 1100);
		options.put("modal", true);
		context.openDialog("UpdateTargetSubjectDialog", options, null);
		log.info("Opening Dialog UpdateTargetSubjectDialog");
	}
	
	/**
	 * Open the Add Target Dialog /Policy Creation/UCON Policy/AddNewTarget
	 */
	public void addTarget() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 380);
		options.put("contentHeight", 230);
		options.put("contentWidth", 365);
		options.put("modal", true);
		context.openDialog("/Policy Creation/UCON Policy/AddNewTarget",
				options, null);
		log.info("Opening Dialog /Policy Creation/UCON Policy/AddNewTarget");
	}
	
	/**
	 * Control the Wizard flow for Creating UCON {@code Policy}
	 * @param event the current event of tab
	 * @return return the event that should be displayed next
	 */
	public String onFlowProcess(FlowEvent event) {
		FacesContext context = FacesContext.getCurrentInstance();

		if (event.getOldStep().equals("IdAndPolicy")) {
			if (this.abcPropertiesAuth) {
				if (this.clickedTarget == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select a Target"));
					log.info("As Target is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				}
			} else if (this.abcPropertiesCond) {
				if (this.clickedOblTarget == null
						&& this.clickedConditionTarget == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select a Target and an Obligation"));
					log.info("As Target and and Obligation is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				} else if (this.clickedConditionTarget == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select a Target"));
					log.info("As Target is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				}
			} else {
				if (this.clickedOblTarget == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select a Target"));
					log.info("As Target is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				} else if (this.selectedCondition == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select an Environment"));
					log.info("As Environment is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				} else if (this.clickedOblTarget == null
						&& this.selectedCondition == null) {
					context.addMessage(null, new FacesMessage("Message",
							"Please select a Target and an Environment"));
					log.info("As Target and Environment is not selected so Stay on same Event or Tab");
					return event.getOldStep();
				}
			}
		}
		context.addMessage(null, new FacesMessage("Successful", "Next Page"));
		log.info("Goto Next Event ot Tab");
		return event.getNewStep();
	}
	

}
