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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;
import org.primefaces.event.FlowEvent;

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.entities.ActionMatch;
import com.aislab.accesscontrol.core.entities.Actions;
import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.entities.EnvironmentMatch;
import com.aislab.accesscontrol.core.entities.Environments;
import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.entities.ResourceMatch;
import com.aislab.accesscontrol.core.entities.Resources;
import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.entities.SubjectMatch;
import com.aislab.accesscontrol.core.entities.Subjects;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.ActAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentDAO;
import com.aislab.accesscontrol.core.ui.dao.ResAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceDAO;
import com.aislab.accesscontrol.core.ui.dao.SubAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectDAO;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;
import com.aislab.accesscontrol.core.ui.util.XACMLConstants;

/**
 * A session scoped, managed bean for user interfaces related to {@code Target}.
 * 
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class TargetController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(TargetController.class.getName());

	/**
	 * An instance of {@code TargetDAO} for using methods to access data related
	 * to {@code Target}
	 */
	TargetDAO daoTarget = new TargetDAO();
	/**
	 * An ArrayList of {@code Target} used to display all the existing
	 * {@code Target}s stored in the database.
	 */
	ArrayList<Target> targetList = new ArrayList<Target>();

	/**
	 * An instance of {@code Target} used to store the {@code Target} selected
	 * by the user from the user interface.
	 */
	private Target selectedTarget;

	/**
	 * An ArrayList of {@code Subjects} used to display all the existing
	 * {@code Subjects} instance present corresponding to {@code Target}
	 * instance specified by {@code selectedTarget}.
	 */
	private ArrayList<Subjects> targetSubjectList = new ArrayList<Subjects>();
	/**
	 * An ArrayList of {@code Resources} used to display all the existing
	 * {@code Resources} instance present corresponding to {@code Target}
	 * instance specified by {@code selectedTarget}.
	 */
	private ArrayList<Resources> targetResourceList = new ArrayList<Resources>();
	/**
	 * An ArrayList of {@code Actions} used to display all the existing
	 * {@code Actions} instance present corresponding to {@code Target} instance
	 * specified by {@code selectedTarget}.
	 */
	private ArrayList<Actions> targetActionList = new ArrayList<Actions>();
	/**
	 * An ArrayList of {@code Environments} used to display all the existing
	 * {@code Environments} instance present corresponding to {@code Target}
	 * instance specified by {@code selectedTarget}.
	 */
	private ArrayList<Environments> targetEnvironmentList = new ArrayList<Environments>();

	/**
	 * An {@code ArrayList} variable to provides the available match ids based
	 * on the selected attribute value while adding a {@code Subject},
	 * {@code Resource}, {@code Action} or {@code Environment} instance.
	 */
	public static ArrayList<String> matchIds = new ArrayList<String>();

	/**
	 * A {@code String} instance to store the match id selected while adding a
	 * {@code Subject}, {@code Resource}, {@code Action} or {@code Environment}
	 * instance.
	 */
	private String selectedMatchId = null;;

	/**
	 * Variables For getting instance of Row Selection for Available Subjects in
	 * Target.xhtml
	 */
	private Subject addedTargetSubject;

	/**
	 * Variables For getting instance of Row Selection for Available Resources
	 * in Target.xhtml
	 */
	private Resource addedTargetResource;

	/**
	 * Variables For getting instance of Row Selection for Available Actions in
	 * Target.xhtml
	 */
	private Action addedTargetAction;

	/**
	 * Variables For getting instance of Row Selection for Available
	 * Environments in Target.xhtml
	 */
	private Environment addedTargetEnvironment;

	/**
	 * An instance of {@code Subjects} selected from the list of available
	 * {@code Subjects} corresponding to a {@code Target} instance specified by
	 * {@code selectedTarget} property.
	 */
	private Subjects selectedSubjects;
	/**
	 * An instance of {@code Resources} selected from the list of available
	 * {@code Resources} corresponding to a {@code Target} instance specified by
	 * {@code selectedTarget} property.
	 */
	private Resources selectedResources;
	/**
	 * An instance of {@code Actions} selected from the list of available
	 * {@code Actions} corresponding to a {@code Target} instance specified by
	 * {@code selectedTarget} property.
	 */
	private Actions selectedActions;
	/**
	 * An instance of {@code Environments} selected from the list of available
	 * {@code Environments} corresponding to a {@code Target} instance specified
	 * by {@code selectedTarget} property.
	 */
	private Environments selectedEnvironments;

	/**
	 * A {@code boolean} variable to store the value of {@code mustBePresent}
	 * attribute of a {@code SubjectMatch}, {@code ResourceMatch},
	 * {@code ActionMatch} or {@code EnvironmentMatch} instance.
	 */
	private boolean mustBePresent = false;

	/**
	 * A {@code String} variable to store the updated value of
	 * {@code description} attribute of an existing {@code Target} instance.
	 */
	private String updatedDescription;
	/**
	 * A {@code String} variable to store the updated value of {@code targetId}
	 * attribute of an existing {@code Target} instance.
	 */
	private String updatedTargetId;
	/**
	 * A {@code List} variable used for providing the required format for
	 * creating {@code Target} instance.
	 */
	List<Object[]> subjListTarg;
	/**
	 * A {@code List} variable used for providing the required format for
	 * creating {@code Target} instance.
	 */

	List<Object[]> resListTarg;
	/**
	 * A {@code List} variable used for providing the required format for
	 * creating {@code Target} instance.
	 */

	List<Object[]> actListTarg;
	/**
	 * A {@code List} variable used for providing the required format for
	 * creating {@code Target} instance.
	 */

	List<Object[]> envListTarg;

	/**
	 * An instance of {@code SubjectDAO} for using methods to access data
	 * related to {@code Subject}
	 */
	SubjectDAO daoTargetSubject = new SubjectDAO();
	/**
	 * An instance of {@code SubjectAttributeDAO} for using methods to access
	 * data related to {@code SubjectAttribute}
	 */
	SubjectAttributeDAO daoTargetSubjectAttribute = new SubjectAttributeDAO();
	/**
	 * An instance of {@code SubAttrValuesDAO} for using methods to access data
	 * related to {@code SubAttrValues}
	 */
	SubAttrValuesDAO daoTargetSubjectAttributeValue = new SubAttrValuesDAO();
	/**
	 * An instance of {@code ResourceDAO} for using methods to access data
	 * related to {@code Resource}
	 */
	ResourceDAO daoTargetRes = new ResourceDAO();
	/**
	 * An instance of {@code ResourceAttributeDAO} for using methods to access
	 * data related to {@code ResourceAttribute}
	 */
	ResourceAttributeDAO daoTargetResourceAttribute = new ResourceAttributeDAO();
	/**
	 * An instance of {@code ResAttrValuesDAO} for using methods to access data
	 * related to {@code ResAttrValues}
	 */
	ResAttrValuesDAO daoTargetResourceAttributeValue = new ResAttrValuesDAO();
	/**
	 * An instance of {@code ActionDAO} for using methods to access data related
	 * to {@code Action}
	 */
	ActionDAO daoTargetAction = new ActionDAO();
	/**
	 * An instance of {@code ActionAttributeDAO} for using methods to access
	 * data related to {@code ActionAttribute}
	 */
	ActionAttributeDAO daoTargetActionAttribute = new ActionAttributeDAO();
	/**
	 * An instance of {@code ActAttrValuesDAO} for using methods to access data
	 * related to {@code ActAttrValues}
	 */
	ActAttrValuesDAO daoTargetActionAttributeValue = new ActAttrValuesDAO();
	/**
	 * An instance of {@code EnvironmentDAO} for using methods to access data
	 * related to {@code Environment}
	 */
	EnvironmentDAO daoTargetEnv = new EnvironmentDAO();
	/**
	 * An instance of {@code EnvironmentAttributeDAO} for using methods to
	 * access data related to {@code EnvironmentAttribute}
	 */
	EnvironmentAttributeDAO envattrdaoTarget = new EnvironmentAttributeDAO();
	/**
	 * An instance of {@code EnvAttrValuesDAO} for using methods to access data
	 * related to {@code EnvAttrValues}
	 */
	EnvAttrValuesDAO envattrvaluesdaoTarget = new EnvAttrValuesDAO();

	/**
	 * An instance of {@code SubAttrValues} used to store the
	 * {@code SubAttrValues} selected by the user from the user interface.
	 */
	private SubAttrValues selectedSubValue;
	/**
	 * An instance of {@code ResAttrValues} used to store the
	 * {@code ResAttrValues} selected by the user from the user interface.
	 */
	private ResAttrValues selectedResValue;
	/**
	 * An instance of {@code ActAttrValues} used to store the
	 * {@code ActAttrValues} selected by the user from the user interface.
	 */
	private ActAttrValues selectedActValue;
	/**
	 * An instance of {@code EnvAttrValues} used to store the
	 * {@code EnvAttrValues} selected by the user from the user interface.
	 */
	private EnvAttrValues selectedEnvValue;

	/**
	 * An ArrayList of {@code SubAttrValues} used to display all the existing
	 * {@code SubAttrValues}(s) stored in the database corresponding to a
	 * particular {@code SubjectAttribute} instance.
	 */
	public ArrayList<SubAttrValues> selectedSubAttrValues = new ArrayList<SubAttrValues>();
	/**
	 * An {@code ArrayList} used to display all the available match-id functions
	 * corresponding to a particular {@code SubAttrValues} instance specified by
	 * {@code selectedSubAttrValues} property.
	 */
	public ArrayList<String> selectedSubMatchIds = new ArrayList<String>();

	/**
	 * An ArrayList of {@code ResAttrValues} used to display all the existing
	 * {@code ResAttrValues}(s) stored in the database corresponding to a
	 * particular {@code ResourceAttribute} instance.
	 */
	public ArrayList<ResAttrValues> selectedResAttrValues = new ArrayList<ResAttrValues>();
	/**
	 * An {@code ArrayList} used to display all the available match-id functions
	 * corresponding to a particular {@code ResAttrValues} instance specified by
	 * {@code selectedSubAttrValues} property.
	 */
	public ArrayList<String> selectedResMatchIds = new ArrayList<String>();

	/**
	 * An ArrayList of {@code ActAttrValues} used to display all the existing
	 * {@code ActAttrValues}(s) stored in the database. These
	 * {@code ActAttrValues}(s) are related to a particular
	 * {@code ActionAttribute} instance stored in
	 * {@code selectedActionAttributes}.
	 */
	public ArrayList<ActAttrValues> selectedActAttrValues = new ArrayList<ActAttrValues>();
	/**
	 * An {@code ArrayList} used to display all the available match-id functions
	 * corresponding to a particular {@code ActAttrValues} instance specified by
	 * {@code selectedSubAttrValues} property.
	 */
	public ArrayList<String> selectedActMatchIds = new ArrayList<String>();
	/**
	 * An ArrayList of {@code EnvAttrValues} used to display all the existing
	 * {@code EnvAttrValues}(s) stored in the database corresponding to a
	 * particular {@code EnvironmentAttribute} instance.
	 */
	public ArrayList<EnvAttrValues> selectedEnvAttrValues = new ArrayList<EnvAttrValues>();
	/**
	 * An {@code ArrayList} used to display all the available match-id functions
	 * corresponding to a particular {@code EnvAttrValues} instance specified by
	 * {@code selectedSubAttrValues} property.
	 */
	public ArrayList<String> selectedEnvMatchIds = new ArrayList<String>();

	/**
	 * An instance of {@code Subject} used to store the {@code Subject} selected
	 * by the user from the user interface.
	 */
	public Subject selectedSubject;

	/**
	 * An instance of {@code Resource} used to store the {@code Resource}
	 * selected by the user from the user interface.
	 */
	private Resource selectedResource;

	/**
	 * An instance of {@code Environment} used to store the {@code Environment}
	 * selected by the user from the user interface.
	 */
	private Environment selectedEnvironment;
	/**
	 * An instance of {@code Action} used to store the {@code Action} selected
	 * by the user from the user interface.
	 */
	private Action selectedAction;

	/**
	 * An instance of {@code EnvironmentAttribute} used to store the
	 * {@code EnvironmentAttribute} selected by the user from the user
	 * interface.
	 */
	private EnvironmentAttribute selectedEnvironmentAttribute;
	/**
	 * An instance of {@code ActionAttribute} used to store the
	 * {@code ActionAttribute} selected by the user from the user interface.
	 */
	private ActionAttribute selectedActionAttributes;
	/**
	 * An instance of {@code ResourceAttribute} used to store the
	 * {@code ResourceAttribute} selected by the user from the user interface.
	 */
	private ResourceAttribute selectedResourceAttribute;
	/**
	 * An instance of {@code SubjectAttribute} used to store the
	 * {@code SubjectAttribute} selected by the user from the user interface.
	 */
	private SubjectAttribute selectedSubjectAttributes;
	/**
	 * List of all Subject that can be added to a Target.
	 */
	/**
	 * An {@code ArrayList} of all the available {@code Subject} instances that
	 * can be added to a {@code Target} instance.
	 */
	public ArrayList<Subject> targetSubjects = new ArrayList<Subject>();
	/**
	 * An {@code ArrayList} of all the available {@code Resource} instances that
	 * can be added to a {@code Target} instance.
	 */
	public ArrayList<Resource> targetResources = new ArrayList<Resource>();
	/**
	 * An {@code ArrayList} of all the available {@code Action} instances that
	 * can be added to a {@code Target} instance.
	 */
	public ArrayList<Action> targetActions = new ArrayList<Action>();
	/**
	 * An {@code ArrayList} of all the available {@code Environment} instances
	 * that can be added to a {@code Target} instance.
	 */
	public ArrayList<Environment> targetEnvironments = new ArrayList<Environment>();

	/**
	 * An ArrayList of {@code SubjectAttribute} used to display all the
	 * available {@code SubjectAttribute} instances corresponding to a
	 * particular {@code Subject} instance.
	 */
	public ArrayList<SubjectAttribute> allSubAttributes = new ArrayList<SubjectAttribute>();

	/**
	 * An ArrayList of {@code ResourceAttribute} used to display all the
	 * available {@code ResourceAttribute} instances corresponding to a
	 * particular {@code Resource} instance.
	 */
	public ArrayList<ResourceAttribute> allResAttributes = new ArrayList<ResourceAttribute>();

	/**
	 * An ArrayList of {@code ActionAttribute} used to display all the available
	 * {@code ActionAttribute} instances corresponding to a particular
	 * {@code Action} instance.
	 */
	public ArrayList<ActionAttribute> allActAttributes = new ArrayList<ActionAttribute>();

	/**
	 * An ArrayList of {@code EnvironmentAttribute} used to display all the
	 * available {@code EnvironmentAttribute} instances corresponding to a
	 * particular {@code Environment} instance.
	 */
	public ArrayList<EnvironmentAttribute> allEnvAttributes = new ArrayList<EnvironmentAttribute>();
	/**
	 * An ArrayList of {@code SubAttrValues} used to display all the available
	 * {@code SubAttrValues} instances corresponding to a particular
	 * {@code SubjectAttribute} instance.
	 */
	public ArrayList<SubAttrValues> allSubValues = new ArrayList<SubAttrValues>();
	/**
	 * An ArrayList of {@code ResAttrValues} used to display all the available
	 * {@code ResAttrValues} instances corresponding to a particular
	 * {@code ResourceAttribute} instance.
	 */
	public ArrayList<ResAttrValues> allResValues = new ArrayList<ResAttrValues>();
	/**
	 * An ArrayList of {@code ActAttrValues} used to display all the available
	 * {@code ActAttrValues} instances corresponding to a particular
	 * {@code ActionAttribute} instance.
	 */
	public ArrayList<ActAttrValues> allActValues = new ArrayList<ActAttrValues>();
	/**
	 * An ArrayList of {@code EnvAttrValues} used to display all the available
	 * {@code EnvAttrValues} instances corresponding to a particular
	 * {@code EnvironmentAttribute} instance.
	 */
	public ArrayList<EnvAttrValues> allEnvValues = new ArrayList<EnvAttrValues>();

	/**
	 * A boolean variable to check whether any {@code Target} instance is
	 * selected by the user so that the corresponding {@code Subject},
	 * {@code Resource}, {@code Action} and {@code Environment} instance can be
	 * added. By default it is set to {@code TRUE} so that the corresponding add
	 * button is disabled while it is becomes {@code FALSE} if any
	 * {@code Target} instance is selected in the user interface.
	 */
	boolean addbtn = true;
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
	 * Sets the {@code addbtn} property to {@code boolean} argument.
	 * 
	 * @param addbtn
	 */
	public void setAddbtn(boolean addbtn) {
		this.addbtn = addbtn;
		log.debug("Set  addbtn: " + addbtn);
	}

	/**
	 * Sets the {@code targetSubjectList} property to {@code targetSubjectList}
	 * argument.
	 * 
	 * @param targetSubjectList
	 */
	public void setTargetSubjectList(ArrayList<Subjects> targetSubjectList) {
		this.targetSubjectList = targetSubjectList;
		log.debug("Set  targetSubjectList: " + targetSubjectList);
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
	 * Sets the {@code targetActionList} property to {@code ArrayList} argument.
	 * 
	 * @param targetActionList
	 */
	public void setTargetActionList(ArrayList<Actions> targetActionList) {
		this.targetActionList = targetActionList;
		log.debug("Set  targetActionList: " + targetActionList);
	}

	/**
	 * Sets the {@code targetEnvironmentList} property to {@code ArrayList}
	 * argument.
	 * 
	 * @param targetEnvironmentList
	 */
	public void setTargetEnvironmentList(
			ArrayList<Environments> targetEnvironmentList) {
		this.targetEnvironmentList = targetEnvironmentList;
		log.debug("Set  targetEnvironmentList: " + targetEnvironmentList);
	}

	/**
	 * Sets the {@code selectedTarget} property to {@code Target} argument.
	 * 
	 * @param selectedTarget
	 */
	public void setSelectedTarget(Target selectedTarget) {
		this.selectedTarget = selectedTarget;
		log.debug("Set  selectedTarget: " + selectedTarget);
	}

	/**
	 * Sets the {@code targetResourceList} property to {@code ArrayList}
	 * argument.
	 * 
	 * @param targetResourceList
	 */
	public void setTargetResourceList(ArrayList<Resources> targetResourceList) {
		this.targetResourceList = targetResourceList;
		log.debug("Set  targetResourceList: " + targetResourceList);
	}

	/**
	 * Sets the {@code selectedEnvironment} property to {@code Environment}
	 * argument.
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
	 * Sets the {@code targetList} property to {@code ArrayList} argument.
	 * 
	 * @param targetList
	 */
	public void setTargetList(ArrayList<Target> targetList) {
		this.targetList = targetList;
		log.debug("Set  targetList: " + targetList);
	}

	/**
	 * Sets the {@code allActValues} property to {@code ArrayList} argument.
	 * 
	 * @param allActValues
	 */
	public void setAllActValues(ArrayList<ActAttrValues> allActValues) {
		this.allActValues = allActValues;
		log.debug("Set  allActValues: " + allActValues);
	}

	/**
	 * Sets the {@code selectedSubjectAttributes} property to
	 * {@code SubjectAttribute} argument.
	 * 
	 * @param selectedSubjectAttributes
	 */
	public void setSelectedSubjectAttributes(
			SubjectAttribute selectedSubjectAttributes) {
		this.selectedSubjectAttributes = selectedSubjectAttributes;
		log.debug("Set  selectedSubjectAttributes: "
				+ selectedSubjectAttributes);
	}

	/**
	 * Sets the {@code selectedResourceAttribute} property to
	 * {@code ResourceAttribute} argument.
	 * 
	 * @param selectedResourceAttributes
	 */
	public void setSelectedResourceAttribute(
			ResourceAttribute selectedResourceAttributes) {
		this.selectedResourceAttribute = selectedResourceAttributes;
		log.debug("Set  selectedResourceAttribute: "
				+ selectedResourceAttribute);
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
	 * Sets the {@code daoTarget} property to {@code TargetDAO} argument.
	 * 
	 * @param daoTarget
	 */
	public void setDaoTarget(TargetDAO daoTarget) {
		this.daoTarget = daoTarget;
		log.debug("Set  daoTarget: " + daoTarget);
	}

	/**
	 * Sets the {@code selectedEnvironmentAttribute} property to
	 * {@code EnvironmentAttribute} argument.
	 * 
	 * @param selectedEnvironmentAttribute
	 */
	public void setSelectedEnvironmentAttribute(
			EnvironmentAttribute selectedEnvironmentAttribute) {
		this.selectedEnvironmentAttribute = selectedEnvironmentAttribute;
		log.debug("Set  selectedEnvironmentAttribute: "
				+ selectedEnvironmentAttribute);
	}

	/**
	 * Sets the {@code allEnvAttributes} property to {@code ArrayList} argument.
	 * 
	 * @param allEnvAttributes
	 */
	public void setAllEnvAttributes(
			ArrayList<EnvironmentAttribute> allEnvAttributes) {
		this.allEnvAttributes = allEnvAttributes;
		log.debug("Set  allEnvAttributes: " + allEnvAttributes);
	}

	/**
	 * Sets the {@code allEnvValues} property to {@code ArrayList} argument.
	 * 
	 * @param allEnvValues
	 */
	public void setAlEnvValues(ArrayList<EnvAttrValues> allEnvValues) {
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
	 * Sets the {@code mustBePresent} property to {@code boolean} argument.
	 * 
	 * @param mustBePresent
	 */
	public void setMustBePresent(boolean mustBePresent) {
		this.mustBePresent = mustBePresent;
		log.debug("Set  mustBePresent: " + mustBePresent);
	}

	/**
	 * Sets the {@code allActAttributes} property to {@code ArrayList} argument.
	 * 
	 * @param allActAttributes
	 */
	public void setAllActAttributes(ArrayList<ActionAttribute> allActAttributes) {
		this.allActAttributes = allActAttributes;
		log.debug("Set  allActAttributes: " + allActAttributes);
	}

	/**
	 * Sets the {@code selectedActionAttributes} property to
	 * {@code ActionAttribute} argument.
	 * 
	 * @param selectedActionAttributes
	 */
	public void setSelectedActionAttributes(
			ActionAttribute selectedActionAttributes) {
		this.selectedActionAttributes = selectedActionAttributes;
		log.debug("Set  selectedActionAttributes: " + selectedActionAttributes);
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
	 * Sets the {@code selectedEnvValue} property to {@code EnvAttrValues}
	 * argument.
	 * 
	 * @param selectedEnvValue
	 */
	public void setSelectedEnvValue(EnvAttrValues selectedEnvValue) {
		this.selectedEnvValue = selectedEnvValue;
		log.debug("Set  selectedEnvValue: " + selectedEnvValue);
	}

	/**
	 * Sets the {@code selectedResValue} property to {@code ResAttrValues}
	 * argument.
	 * 
	 * @param selectedResValue
	 */
	public void setSelectedResValue(ResAttrValues selectedResValue) {
		this.selectedResValue = selectedResValue;
		log.debug("Set  selectedResValue: " + selectedResValue);
	}

	/**
	 * Sets the {@code selectedSubValue} property to {@code SubAttrValues}
	 * argument.
	 * 
	 * @param selectedSubValue
	 */
	public void setSelectedSubValue(SubAttrValues selectedSubValue) {
		this.selectedSubValue = selectedSubValue;
		log.debug("Set  selectedSubValue: " + selectedSubValue);
	}

	/**
	 * Sets the {@code selectedActValue} property to {@code ActAttrValues}
	 * argument.
	 * 
	 * @param selectedActValue
	 */
	public void setSelectedActValue(ActAttrValues selectedActValue) {
		this.selectedActValue = selectedActValue;
		log.debug("Set  selectedActValue: " + selectedActValue);
	}

	/**
	 * Sets the {@code addedTargetEnvironment} property to {@code Environment}
	 * argument.
	 * 
	 * @param addedTargetEnvironment
	 */
	public void setAddedTargetEnvironment(Environment addedTargetEnvironment) {
		this.addedTargetEnvironment = addedTargetEnvironment;
		log.debug("Set  addedTargetEnvironment: " + addedTargetEnvironment);
	}

	/**
	 * Sets the {@code addedTargetResource} property to {@code Resource}
	 * argument.
	 * 
	 * @param addedTargetResource
	 */
	public void setAddedTargetResource(Resource addedTargetResource) {
		this.addedTargetResource = addedTargetResource;
		log.debug("Set  addedTargetResource: " + addedTargetResource);
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
	 * Sets the {@code addedTargetAction} property to {@code Action} argument.
	 * 
	 * @param addedTargetAction
	 */
	public void setAddedTargetAction(Action addedTargetAction) {
		this.addedTargetAction = addedTargetAction;
		log.debug("Set  addedTargetAction: " + addedTargetAction);
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
	 * Sets the {@code selectedActions} property to {@code Actions} argument.
	 * 
	 * @param selectedActions
	 */
	public void setSelectedActions(Actions selectedActions) {
		this.selectedActions = selectedActions;
		Action act = daoTarget.getActionFromActions(
				selectedTarget.getPkTarget(), this.selectedActions);
		this.setAddedTargetAction(act);
		log.debug("Set  selectedActions: " + selectedActions);
	}

	/**
	 * Sets the {@code selectedResources} property to {@code Resources}
	 * argument.
	 * 
	 * @param selectedResources
	 */
	public void setSelectedResources(Resources selectedResources) {
		this.selectedResources = selectedResources;
		Resource rs = daoTarget.getResourceFromResources(
				selectedTarget.getPkTarget(), this.selectedResources);
		this.setAddedTargetResource(rs);

		log.debug("Set  selectedResources: " + selectedResources);
	}

	/**
	 * Sets the {@code selectedEnvironments} property to {@code Environments}
	 * argument.
	 * 
	 * @param selectedEnvironments
	 */
	public void setSelectedEnvironments(Environments selectedEnvironments) {
		this.selectedEnvironments = selectedEnvironments;
		Environment env = daoTarget.getEnvironmentByEnvironments(
				selectedTarget.getPkTarget(), this.selectedEnvironments);
		this.setAddedTargetEnvironment(env);
		log.debug("Set  selectedEnvironments: " + selectedEnvironments);
	}

	/**
	 * Sets the {@code selectedSubjects} property to {@code Subjects} argument.
	 * 
	 * @param selectedSubjects
	 */
	public void setSelectedSubjects(Subjects selectedSubjects) {
		this.selectedSubjects = selectedSubjects;

		if (subjListTarg == null) {
			subjListTarg = addForSubjectMatch();
			if (subjListTarg == null)
				subjListTarg = new ArrayList<Object[]>();
		}
		if (subjListTarg.size() <= 0) {
			// System.out.println("It was also Zero !!");
		}
		List<SubjectMatch> subjectMatch = daoTarget
				.createSubjectMatchForUpdate(subjListTarg,
						this.isMustBePresent());
		if (subjectMatch == null) {

			subjectMatch = new ArrayList<SubjectMatch>();
		}
		if (subjectMatch.size() <= 0) {
			// System.out.println("It was Zero !!");
		}
		Subject sb = daoTarget.getSubjectFromSubjects(
				selectedTarget.getPkTarget(), selectedSubjects, subjectMatch);
		subjListTarg = null;

		this.setAddedTargetSubject(sb);
		log.debug("Set  selectedSubjects: " + selectedSubjects);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Returns the value of {@code selectedSubjects} property.
	 * 
	 * @return selectedSubjects
	 */
	public Subjects getSelectedSubjects() {
		log.debug("Get  selectedSubjects: " + selectedSubjects);
		return selectedSubjects;
	}

	/**
	 * Returns the value of {@code selectedResources} property.
	 * 
	 * @return selectedResources
	 */
	public Resources getSelectedResources() {
		log.debug("Get  selectedResources: " + selectedResources);
		return selectedResources;
	}

	/**
	 * Returns the value of {@code selectedActions} property.
	 * 
	 * @return selectedActions
	 */
	public Actions getSelectedActions() {
		log.debug("Get  selectedActions: " + selectedActions);
		return selectedActions;
	}

	/**
	 * Returns the value of {@code selectedEnvironments} property.
	 * 
	 * @return selectedEnvironments
	 */
	public Environments getSelectedEnvironments() {
		log.debug("Get  selectedEnvironments: " + selectedEnvironments);
		return selectedEnvironments;
	}

	/**
	 * Returns the value of {@code selectedMatchId} property.
	 * 
	 * @return selectedMatchId
	 */
	public String getSelectedMatchId() {
		log.debug("Get  selectedMatchId: " + selectedMatchId);
		return selectedMatchId;
	}

	/**
	 * Returns the value of {@code allEnvValues} property.
	 * 
	 * @return allEnvValues
	 */
	public ArrayList<EnvAttrValues> getAllEnvValues() {
		if (selectedEnvironmentAttribute != null) {
			log.debug("Getting  allEnvValues ");
			return (ArrayList<EnvAttrValues>) envattrvaluesdaoTarget
					.selectEnvAttrValue(selectedEnvironmentAttribute
							.getPkEnvAttr());
		}
		log.debug("Get  allEnvValues: " + null);
		return null;

	}

	/**
	 * Returns the value of {@code allEnvAttributes} property.
	 * 
	 * @return allEnvAttributes
	 */
	public ArrayList<EnvironmentAttribute> getAllEnvAttributes() {
		if (selectedEnvironment != null) {
			log.debug("Getting allEnvAttributes ");
			return (ArrayList<EnvironmentAttribute>) envattrdaoTarget
					.selectEnvironmentAttributes(selectedEnvironment
							.getPkEnvironment());
		}
		log.debug("Get  allEnvAttributes: " + null);
		return null;

	}

	/**
	 * Returns the value of {@code selectedEnvironmentAttribute} property.
	 * 
	 * @return selectedEnvironmentAttribute
	 */
	public EnvironmentAttribute getSelectedEnvironmentAttribute() {
		log.debug("Get  selectedEnvironmentAttribute: "
				+ selectedEnvironmentAttribute);
		return selectedEnvironmentAttribute;
	}

	/**
	 * Returns the value of {@code updatedDescription} property.
	 * 
	 * @return updatedDescription
	 */
	public String getUpdatedDescription() {
		if (selectedTarget != null) {
			this.updatedDescription = selectedTarget.getDescription();
		}
		log.debug("Get  updatedDescription: " + updatedDescription);

		return updatedDescription;
	}

	/**
	 * Returns the value of {@code updatedTargetId} property.
	 * 
	 * @return updatedTargetId
	 */
	public String getUpdatedTargetId() {
		if (selectedTarget != null) {
			this.updatedTargetId = selectedTarget.getTargetId();
		}
		log.debug("Get  updatedTargetId: " + updatedTargetId);

		return updatedTargetId;
	}

	/**
	 * Returns the value of {@code addedTargetSubject} property.
	 * 
	 * @return addedTargetSubject
	 */
	public Subject getAddedTargetSubject() {
		log.debug("Get  addedTargetSubject: " + addedTargetSubject);
		return addedTargetSubject;
	}

	/**
	 * Returns the value of {@code addedTargetResource} property.
	 * 
	 * @return addedTargetResource
	 */
	public Resource getAddedTargetResource() {
		log.debug("Get  addedTargetResource: " + addedTargetResource);
		return addedTargetResource;
	}

	/**
	 * Returns the value of {@code addedTargetAction} property.
	 * 
	 * @return addedTargetAction
	 */
	public Action getAddedTargetAction() {
		log.debug("Get  addedTargetAction: " + addedTargetAction);
		return addedTargetAction;
	}

	/**
	 * Returns the value of {@code addedTargetEnvironment} property.
	 * 
	 * @return addedTargetEnvironment
	 */
	public Environment getAddedTargetEnvironment() {
		log.debug("Get  addedTargetEnvironment: " + addedTargetEnvironment);
		return addedTargetEnvironment;
	}

	/**
	 * Returns the value of {@code targetList} property.
	 * 
	 * @return targetList
	 */
	public ArrayList<Target> getTargetList() {
		ArrayList<Target> targets = (ArrayList<Target>) daoTarget
				.selectTarget();
		log.debug("Get  TargetList: " + targets);

		return targets;
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
	 * Returns the value match id and attribute value corresponding to the
	 * {@code Subjects} argument.
	 * 
	 * @param s
	 * @return String
	 */
	public String getMatchIdAndValueS(Subjects s) {
		log.debug("Getting MatchIdAndValueS ");
		return daoTarget.getMatchIdAndValue(s);
	}

	/**
	 * Returns the value match id and attribute value corresponding to the
	 * {@code Resources} argument.
	 * 
	 * @param r
	 * @return String
	 */
	public String getMatchIdAndValueR(Resources r) {
		log.debug("Getting MatchIdAndValueR ");
		return daoTarget.getMatchIdAndValue(r);
	}

	/**
	 * Returns the value match id and attribute value corresponding to the
	 * {@code Actions} argument.
	 * 
	 * @param a
	 * @return String
	 */
	public String getMatchIdAndValueA(Actions a) {
		log.debug("Getting MatchIdAndValueA ");
		return daoTarget.getMatchIdAndValue(a);
	}

	/**
	 * Returns the value match id and attribute value corresponding to the
	 * {@code Environments} argument.
	 * 
	 * @param e
	 * @return String
	 */
	public String getMatchIdAndValueE(Environments e) {
		log.debug("Getting MatchIdAndValueE ");
		return daoTarget.getMatchIdAndValue(e);
	}

	/**
	 * Returns the value of {@code splittedMatchIds} property.
	 * 
	 * @param matchID
	 * @return splittedMatchIds
	 */
	public String getSplittedMatchId(String matchID) {
		String[] splittedMatchIds = matchID.split(":");
		log.debug("Get  splittedMatchId: " + splittedMatchIds[7]);
		return splittedMatchIds[7];
	}

	/**
	 * Returns the value of {@code mustBePresent} property.
	 * 
	 * @return mustBePresent
	 */
	public boolean isMustBePresent() {
		log.debug("Get  mustBePresent: " + mustBePresent);
		return mustBePresent;
	}

	/**
	 * Returns {@code FALSE} if an instance of the {@code Target} is selected by
	 * the user otherwise TRUE.
	 * 
	 * @return
	 */
	public boolean isAddbtn() {
		log.debug("Get  addbtn: " + addbtn);
		return addbtn;
	}

	/**
	 * Returns the value of {@code targetSubjectList} property.
	 * 
	 * @return targetSubjectList
	 */
	public ArrayList<Subjects> getTargetSubjectList() {
		if (selectedTarget != null) {
			ArrayList<Subjects> targetSubs = (ArrayList<Subjects>) daoTarget
					.populateTargetSubjects(selectedTarget.getPkTarget());
			int i = 0;
			for (Subjects s : targetSubs) {

				i++;
			}
			log.debug("Get  targetSubjectList: " + targetSubs);

			return targetSubs;
		}
		log.debug("Get  targetSubjectList: " + null);

		return null;
	}

	/**
	 * Returns the value of {@code targetResourceList} property.
	 * 
	 * @return targetResourceList
	 */
	public ArrayList<Resources> getTargetResourceList() {
		if (selectedTarget != null) {
			log.debug("Getting  targetResourceList ");
			return (ArrayList<Resources>) daoTarget
					.populateTargetSubjectsResources(selectedTarget
							.getPkTarget());
		}
		log.debug("Get  targetResourceList: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code targetActionList} property.
	 * 
	 * @return targetActionList
	 */
	public ArrayList<Actions> getTargetActionList() {
		if (selectedTarget != null) {
			log.debug("Getting targetActionList ");
			return (ArrayList<Actions>) daoTarget
					.populateTargetActions(selectedTarget.getPkTarget());
		}
		log.debug("Get  targetActionList: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code targetEnvironmentList} property.
	 * 
	 * @return targetEnvironmentList
	 */
	public ArrayList<Environments> getTargetEnvironmentList() {
		if (selectedTarget != null) {
			log.debug("Getting targetEnvironmentList ");
			return (ArrayList<Environments>) daoTarget
					.populateTargetEnvironments(selectedTarget.getPkTarget());
		}
		log.debug("Get  targetEnvironmentList: " + null);

		return null;
	}

	/**
	 * Returns the value of {@code selectedSubValue} property.
	 * 
	 * @return selectedSubValue
	 */
	public SubAttrValues getSelectedSubValue() {
		log.debug("Get  selectedSubValue: " + selectedSubValue);
		return selectedSubValue;
	}

	/**
	 * Returns the value of {@code selectedActValue} property.
	 * 
	 * @return selectedActValue
	 */
	public ActAttrValues getSelectedActValue() {
		log.debug("Get  selectedActValue: " + selectedActValue);
		return selectedActValue;
	}

	/**
	 * Returns the value of {@code selectedResValue} property.
	 * 
	 * @return selectedResValue
	 */
	public ResAttrValues getSelectedResValue() {
		log.debug("Get  selectedResValue: " + selectedResValue);
		return selectedResValue;
	}

	/**
	 * Returns the value of {@code selectedEnvValue} property.
	 * 
	 * @return selectedEnvValue
	 */
	public EnvAttrValues getSelectedEnvValue() {
		log.debug("Get  selectedEnvValue: " + selectedEnvValue);
		return selectedEnvValue;
	}

	/**
	 * Returns the value of {@code selectedAction} property.
	 * 
	 * @return selectedAction
	 */
	public Action getSelectedAction() {
		log.debug("Get  selectedAction: " + selectedAction);
		return selectedAction;
	}

	/**
	 * Returns the value of {@code selectedActionAttributes} property.
	 * 
	 * @return selectedActionAttributes
	 */
	public ActionAttribute getSelectedActionAttributes() {
		log.debug("Get  selectedActionAttributes: " + selectedActionAttributes);
		return selectedActionAttributes;
	}

	/**
	 * Returns the value of {@code allResAttributes} property.
	 * 
	 * @return allResAttributes
	 */
	public ArrayList<ResourceAttribute> getAllResAttributes() {
		if (selectedResource != null) {
			log.debug("Getting allResAttributes ");
			return (ArrayList<ResourceAttribute>) daoTargetResourceAttribute
					.selectResourceAttributes(selectedResource.getPkResource());
		} else {
			log.debug("Get  allResAttributes: " + null);
			return null;
		}

	}

	/**
	 * Returns the value of {@code targetActions} property.
	 * 
	 * @return targetActions
	 */
	public ArrayList<Action> getTargetActions() {
		log.debug("Getting targetActions ");
		return (ArrayList<Action>) daoTargetAction.selectAction();
	}

	/**
	 * Returns the value of {@code targetResources} property.
	 * 
	 * @return targetResources
	 */
	public ArrayList<Resource> getTargetResources() {
		log.debug("Getting targetResources");

		return (ArrayList<Resource>) daoTargetRes.selectResource();
	}

	/**
	 * Returns the value of {@code targetSubjects} property.
	 * 
	 * @return targetSubjects
	 */
	public ArrayList<Subject> getTargetSubjects() {

		log.debug("Getting targetSubjects ");
		return (ArrayList<Subject>) daoTargetSubject.selectSubject();
	}

	/**
	 * Returns the value of {@code matchIds} property.
	 * 
	 * @return matchIds
	 */
	public ArrayList<String> getMatchIds() {
		log.debug("Get  matchIds: " + matchIds);

		return this.matchIds;
	}

	/**
	 * Returns the value of {@code targetEnvironments} property.
	 * 
	 * @return targetEnvironments
	 */
	public ArrayList<Environment> getTargetEnvironments() {
		log.debug("Getting targetEnvironments ");
		return (ArrayList<Environment>) daoTargetEnv.selectEnvironment();
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
	 * Returns the value of {@code selectedSubject} property.
	 * 
	 * @return selectedSubject
	 */
	public Subject getSelectedSubject() {
		log.debug("Get  selectedSubject: " + selectedSubject);
		return selectedSubject;
	}

	/**
	 * Returns the value of {@code selectedResource} property.
	 * 
	 * @return selectedResource
	 */
	public Resource getSelectedResource() {
		log.debug("Get  selectedResource: " + selectedResource);
		return selectedResource;

	}

	/**
	 * Returns the value of {@code allSubAttributes} property.
	 * 
	 * @return allSubAttributes
	 */
	public ArrayList<SubjectAttribute> getAllSubAttributes() {
		if (selectedSubject != null) {
			log.debug("Getting  allSubAttributes ");
			return (ArrayList<SubjectAttribute>) daoTargetSubjectAttribute
					.selectSubjectAttributes(selectedSubject.getPkSubject());

		} else {
			log.debug("Get  allSubAttributes: " + null);
			return null;
		}
	}

	/**
	 * Returns the value of {@code selectedEnvironment} property.
	 * 
	 * @return selectedEnvironment
	 */

	public Environment getSelectedEnvironment() {
		log.debug("Get  selectedEnvironment: " + selectedEnvironment);
		return selectedEnvironment;
	}

	/**
	 * Returns the value of {@code allSubValues} property.
	 * 
	 * @return allSubValues
	 */
	public ArrayList<SubAttrValues> getAllSubValues() {
		if (selectedSubjectAttributes != null) {
			log.debug("Getting  allSubValues ");
			return (ArrayList<SubAttrValues>) daoTargetSubjectAttributeValue
					.populateSubValueList(selectedSubjectAttributes
							.getPkSubAttr());

		}
		log.debug("Get  allSubValues: " + null);
		return null;
	}

	/**
	 * Returns the value of {@code allResValues} property.
	 * 
	 * @return allResValues
	 */
	public ArrayList<ResAttrValues> getAllResValues() {
		if (selectedResourceAttribute != null) {
			log.debug("Getting  allResValues ");
			return (ArrayList<ResAttrValues>) daoTargetResourceAttributeValue
					.populateResValueList(selectedResourceAttribute
							.getPkResAttr());
		}
		{
			log.debug("Get  allResValues: " + null);
			return null;
		}
	}

	/**
	 * Returns the value of {@code selectedSubjectAttributes} property.
	 * 
	 * @return selectedSubjectAttributes
	 */
	public SubjectAttribute getSelectedSubjectAttributes() {
		log.debug("Get  selectedSubjectAttributes: "
				+ selectedSubjectAttributes);
		return selectedSubjectAttributes;
	}

	/**
	 * Returns the value of {@code selectedResourceAttribute} property.
	 * 
	 * @return selectedResourceAttribute
	 */
	public ResourceAttribute getSelectedResourceAttribute() {
		log.debug("Get  selectedResourceAttribute: "
				+ selectedResourceAttribute);
		return selectedResourceAttribute;
	}

	/**
	 * Returns the value of {@code allActAttributes} property.
	 * 
	 * @return allActAttributes
	 */
	public ArrayList<ActionAttribute> getAllActAttributes() {
		if (selectedAction != null) {
			log.debug("Getting  allActAttributes ");
			return (ArrayList<ActionAttribute>) daoTargetActionAttribute
					.selectActionAttributes(selectedAction.getPkAction());
		}
		log.debug("Get  allActAttributes: " + null);
		return null;

	}

	/**
	 * Returns the value of {@code allActValues} property.
	 * 
	 * @return allActValues
	 */
	public ArrayList<ActAttrValues> getAllActValues() {
		if (selectedActionAttributes != null) {
			log.debug("Getting  allActValues ");

			return (ArrayList<ActAttrValues>) daoTargetActionAttributeValue
					.populateActValueList(selectedActionAttributes
							.getPkActAttr());
		}
		log.debug("Get  allActValues: " + null);

		return null;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Opens the {@code /Policy Creation/Target/Add/AddNewTarget.xhtml} file in
	 * a Primefaces {@code  Dialog} component which offers the functionality of
	 * adding a new {@code Target} instance.
	 */
	public void addTarget() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 580);
		options.put("contentHeight", 230);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Target/Add/AddNewTarget in a dialog.");

		context.openDialog("/Policy Creation/Target/Add/AddNewTarget", options,
				null);
	}

	/**
	 * Transforms the Subject data to the format required by the query for
	 * inserting data.
	 * 
	 * @return data in the required format
	 */
	public List<Object[]> addForSubjectMatch() {
		List<Object[]> subMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedSubAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (SubAttrValues) selectedSubAttrValues.get(j);
			temp[1] = (String) selectedSubMatchIds.get(j);
			subMatch.add(temp);
		}
		return subMatch;
	}

	/**
	 * Transforms the Resource data to the format required by the query for
	 * inserting data.
	 * 
	 * @return data in the required format
	 */
	public List<Object[]> addForResourceMatch() {
		List<Object[]> resMatch = new ArrayList<Object[]>();

		for (int j = 0; j < selectedResAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (ResAttrValues) selectedResAttrValues.get(j);
			temp[1] = (String) selectedResMatchIds.get(j);
			resMatch.add(temp);
		}
		return resMatch;
	}

	/**
	 * Transforms the Action data to the format required by the query for
	 * inserting data.
	 * 
	 * @return data in the required format
	 */
	public List<Object[]> addForActionMatch() {
		List<Object[]> actMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedActAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (ActAttrValues) selectedActAttrValues.get(j);
			temp[1] = (String) selectedActMatchIds.get(j);
			actMatch.add(temp);
		}
		return actMatch;
	}

	/**
	 * Transforms the Environment data to the format required by the query for
	 * inserting data.
	 * 
	 * @return data in the required format
	 */
	public List<Object[]> addForEnvironmentMatch() {
		List<Object[]> envMatch = new ArrayList<Object[]>();
		for (int j = 0; j < selectedEnvAttrValues.size(); j++) {
			Object temp[] = new Object[2];
			temp[0] = (EnvAttrValues) selectedEnvAttrValues.get(j);
			temp[1] = (String) selectedEnvMatchIds.get(j);
			envMatch.add(temp);
		}
		return envMatch;
	}

	/**
	 * Adds a Subject value to selection lists
	 */
	public void addSubToSelection() {
		selectedSubAttrValues = new ArrayList<SubAttrValues>();
		selectedSubMatchIds = new ArrayList<String>();
		if (selectedTarget != null) {
			List<Subjects> subjects = daoTarget
					.populateTargetSubjects(selectedTarget.getPkTarget());
			Iterator<Subjects> subjIter = subjects.iterator();
			int k = 0;
			while (subjIter.hasNext()) {
				Subjects sub = (Subjects) subjIter.next();
				SubAttrValues subValues = daoTarget
						.getRequiredSubjectAttributeValue(sub);
				String subMatchId = daoTarget.getMatchId(sub);
				selectedSubAttrValues.add(subValues);
				selectedSubMatchIds.add(subMatchId);
				k++;

			}
			this.selectedSubAttrValues.add(this.selectedSubValue);
			this.selectedSubMatchIds.add(this.selectedMatchId);

		}
	}

	/**
	 * Adds a Resource value to selection lists
	 */
	public void addResToSelection() {
		if (selectedResource != null && selectedResourceAttribute != null
				&& selectedResValue != null && selectedMatchId != null) {
			selectedResAttrValues = new ArrayList<ResAttrValues>();
			selectedResMatchIds = new ArrayList<String>();
			if (selectedTarget != null) {

				List<Resources> resources = daoTarget
						.populateTargetSubjectsResources(selectedTarget
								.getPkTarget());
				Iterator<Resources> resIter = resources.iterator();
				int k = 0;
				while (resIter.hasNext()) {
					Resources res = (Resources) resIter.next();
					ResAttrValues resValues = daoTarget
							.getRequiredResourceAttributeValue(res);
					String resMatchId = daoTarget.getMatchId(res);
					selectedResAttrValues.add(resValues);
					selectedResMatchIds.add(resMatchId);
					k++;

				}
				this.selectedResAttrValues.add(this.selectedResValue);
				this.selectedResMatchIds.add(this.selectedMatchId);
			}

		}
	}

	/**
	 * For adding a Action value to selection lists
	 */
	public void addActToSelection() {
		if (selectedAction != null && selectedActionAttributes != null
				&& selectedActValue != null && selectedMatchId != null) {
			selectedActAttrValues = new ArrayList<ActAttrValues>();
			selectedActMatchIds = new ArrayList<String>();
			if (selectedTarget != null) {

				List<Actions> actions = daoTarget
						.populateTargetActions(selectedTarget.getPkTarget());
				Iterator<Actions> actIter = actions.iterator();
				int k = 0;
				while (actIter.hasNext()) {
					Actions acts = (Actions) actIter.next();
					ActAttrValues actValues = daoTarget
							.getRequiredActionAttributeValue(acts);
					String actMatchId = daoTarget.getMatchId(acts);
					selectedActAttrValues.add(actValues);
					selectedActMatchIds.add(actMatchId);
					k++;

				}
				this.selectedActAttrValues.add(selectedActValue);
				this.selectedActMatchIds.add(selectedMatchId);

			}
		}
	}

	/**
	 * For adding a Environment value to selection lists
	 */
	public void addEnvToSelection() {
		if (selectedEnvironment != null && selectedEnvironmentAttribute != null
				&& selectedEnvValue != null && selectedMatchId != null) {
			selectedEnvAttrValues = new ArrayList<EnvAttrValues>();
			selectedEnvMatchIds = new ArrayList<String>();
			if (selectedTarget != null) {

				List<Environments> environments = daoTarget
						.populateTargetEnvironments(selectedTarget
								.getPkTarget());
				Iterator<Environments> envIter = environments.iterator();
				int k = 0;
				while (envIter.hasNext()) {
					Environments env = (Environments) envIter.next();
					EnvAttrValues envValues = daoTarget
							.getRequiredEnvironmentAttributeValue(env);
					String envMatchId = daoTarget.getMatchId(env);
					selectedEnvAttrValues.add(envValues);
					selectedEnvMatchIds.add(envMatchId);
					k++;

				}
				this.selectedEnvAttrValues.add(this.selectedEnvValue);
				this.selectedEnvMatchIds.add(this.selectedMatchId);
			}

		}
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Enables the buttons for adding {@code Subject}, {@code Resource},
	 * {@code Action} and {@code Environment} instances corresponding to an
	 * existing {@code Target} instance.
	 */
	public void onTargetSelected() {
		this.setAddbtn(false);
	}

	/**
	 * Disables the buttons for adding {@code Subject}, {@code Resource},
	 * {@code Action} and {@code Environment} instances corresponding to an
	 * existing {@code Target} instance.
	 */
	void onTargetUnSelected() {
		this.setAddbtn(true);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Deletes the selected {@code Subject} instance from the selected
	 * {@code Target} instance.
	 */
	public void deleteSubject() {
		if (this.addedTargetSubject != null) {
			daoTarget.deleteSubject(selectedTarget.getPkTarget(),
					selectedSubjects, this.addedTargetSubject);
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		}

		else { // System.out.println("error in delete subject -------");
		}
	}

	/**
	 * Deletes the selected {@code Resource} instance from the selected
	 * {@code Target} instance.
	 */
	public void deleteResource() {
		daoTarget.deleteResource(selectedTarget.getPkTarget(),
				this.selectedResources, this.addedTargetResource);
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
	}

	/**
	 * Deletes the selected {@code Action} instance from the selected
	 * {@code Target} instance.
	 */
	public void deleteAction() {
		daoTarget.deleteAction(selectedTarget.getPkTarget(), selectedActions,
				this.addedTargetAction);
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));

	}

	/**
	 * Deletes the selected {@code Environment} instance from the selected
	 * {@code Target} instance.
	 */
	public void deleteEnvironment() {
		daoTarget.deleteEnvironment(selectedTarget.getPkTarget(),
				selectedEnvironments, this.addedTargetEnvironment);
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
	}

	/**
	 * Deletes the selected {@code Target} instance specified by the
	 * {@code selectedTarget} property.
	 */
	public void deleteTarget() {
		if (selectedTarget != null) {
			daoTarget.deleteTarget(selectedTarget.getPkTarget());
			selectedTarget = null;
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		} else {
			RequestContext context = RequestContext.getCurrentInstance();
			context.execute("noTargetDialog.show()");
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Opens the
	 * {@code /Policy Creation/Target/Add/AddNewTargetEnvironmentDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating an existing {@code Target} instance by adding
	 * an {@code Environment} instance to it.
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
		log.info("Opening /Policy Creation/Target/Add/AddNewTargetEnvironmentDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Target/Add/AddNewTargetEnvironmentDialog",
				options, null);
	}

	/**
	 * Opens the {@code /Policy Creation/Target/Update/UpdateTargetDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the name and description of an existing
	 * {@code Target} instance.
	 */
	public void updateTargetByDialog() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 565);
		options.put("contentHeight", 230);
		options.put("contentWidth", 550);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Target/Update/UpdateTargetDialog in a dialog.");

		context.openDialog("/Policy Creation/Target/Update/UpdateTargetDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Target/Add/AddNewTargetSubjectDialog.xhtml} file
	 * in a Primefaces {@code  Dialog} component which offers the functionality
	 * of updating an existing {@code Target} instance by adding an
	 * {@code Subject} instance to it.
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
		log.info("Opening /Policy Creation/Target/Add/AddNewTargetSubjectDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Target/Add/AddNewTargetSubjectDialog",
				options, null);
	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Target/Add/AddNewTargetResourcesDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating an existing {@code Target} instance by adding
	 * an {@code Resource} instance to it.
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
		log.info("Opening /Policy Creation/Target/Add/AddNewTargetResourcesDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Target/Add/AddNewTargetResourcesDialog",
				options, null);
	}

	/**
	 * Opens the
	 * {@code /Policy Creation/Target/Add/AddNewTargetActionDialog.xhtml} file
	 * in a Primefaces {@code  Dialog} component which offers the functionality
	 * of updating an existing {@code Target} instance by adding an
	 * {@code Action} instance to it.
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
		log.info("Opening /Policy Creation/Target/Add/AddNewTargetActionDialog in a dialog.");

		context.openDialog(
				"/Policy Creation/Target/Add/AddNewTargetActionDialog",
				options, null);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Loads all the available Match Ids corresponding to the {@code datatype}
	 * attribute of {@code SubjectAttribute}, {@code ResourcrAttribute},
	 * {@code ActionAttribute} or {@code EnvironmentAttribute} respectively.
	 */
	public void populateMatchId() {
		XACMLConstants xacmlConsts = new XACMLConstants();
		ArrayList<String> allMIds = xacmlConsts.getMatchIds();
		matchIds = new ArrayList<String>();
		if (this.selectedSubValue != null) {
			String dataType = this.selectedSubjectAttributes.getDataType();
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH))) {

							matchIds.add(mId);
						}
					}
				}
			}
		} else if (this.selectedResValue != null) {
			String dataType = this.selectedResourceAttribute.getDataType();
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
		} else if (this.selectedActValue != null) {
			String dataType = this.selectedActionAttributes.getDataType();
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
		} else if (this.selectedEnvValue != null) {
			String dataType = this.selectedEnvironmentAttribute.getDataType();
			if (dataType != null) {
				for (int t = 0; t < allMIds.size(); t++) {
					String mId = allMIds.get(t);
					if (mId != null) {
						if (mId.contains(dataType)
								|| mId.contains(dataType
										.toLowerCase(Locale.ENGLISH)))
							matchIds.add(allMIds.get(t));
					}
				}
			}
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Cancels the operation of updating an existing {@code Target} instance.
	 */
	public void cancelUpdatedTarget() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
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
	}

	/**
	 * Cancels the operation of updating name and description of an existing
	 * {@code Target} instance.
	 */
	public void cancelUpdatedTargetDescription() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Saves the updated value of {@code targetId} and {@code description}
	 * attributes of an existing {@code Target} instance.
	 */
	public void saveUpdatedTargetDescription() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (selectedTarget != null) {
			daoTarget.updateTarget(selectedTarget.getPkTarget(),
					updatedTargetId, updatedDescription);
			this.setOperationFail(false);
		}
		log.info("Closing dialog.");
		context.closeDialog(this);
	}

	/**
	 * Saves the newly added instance of {@code Subjects} corresponding to an
	 * existing {@code Target} instance in the database.
	 * 
	 */
	public void saveUpdatedTargetSubject() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedTarget != null) {
			subjListTarg = addForSubjectMatch();
			if (subjListTarg == null)
				subjListTarg = new ArrayList<Object[]>();

		}

		List<SubjectMatch> subjectMatch = daoTarget.createSubjectMatch(
				subjListTarg, this.isMustBePresent());
		if (subjectMatch == null) {
			subjectMatch = new ArrayList<SubjectMatch>();
		}
		for (int y = 0; y < subjectMatch.size(); y++) {
			SubjectMatch sMatch = (SubjectMatch) subjectMatch.get(y);
			Set<Subjects> s = sMatch.getSubjects();
			SubAttrValues vals = sMatch.getSubAttrValues();
			String matchId = sMatch.getMatchId();

		}

		if (this.selectedMatchId != null && matchIds != null) {
			if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {

				this.setOperationFail(false);
				daoTarget.updateTargetSubjects(selectedTarget.getPkTarget(),
						subjectMatch);
				log.info("Closing dialog.");
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
				this.matchIds = null;
				this.mustBePresent = false;
			} else
				context.execute("noMatchIdDialogs.show()");
		} else {
			context.execute("noMatchIdDialogs.show()");
		}

	}

	/**
	 * Saves the newly added instance of {@code Resources} corresponding to an
	 * existing {@code Target} instance in the database.
	 * 
	 */
	public void saveUpdatedTargetResource() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedTarget != null) {

			resListTarg = addForResourceMatch();
			if (resListTarg == null)
				resListTarg = new ArrayList<Object[]>();
		}
		List<ResourceMatch> resourceMatch = daoTarget.createResourceMatch(
				resListTarg, this.isMustBePresent());
		if (resourceMatch == null)
			resourceMatch = new ArrayList<ResourceMatch>();
		if (this.selectedMatchId != null && matchIds != null) {
			if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
				this.setOperationFail(false);
				daoTarget.updateTargetResources(selectedTarget.getPkTarget(),
						resourceMatch);
				log.info("Closing dialog.");
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

				this.matchIds = null;
				this.mustBePresent = false;
			} else
				context.execute("noMatchIdDialogr.show()");

		} else {

			context.execute("noMatchIdDialogr.show()");
		}

	}

	/**
	 * Saves the newly added instance of {@code Actions} corresponding to an
	 * existing {@code Target} instance in the database.
	 * 
	 */

	public void saveUpdatedTargetAction() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedTarget != null) {
			actListTarg = addForActionMatch();
			if (actListTarg == null)
				actListTarg = new ArrayList<Object[]>();

			List<ActionMatch> actionMatch = daoTarget.createActionMatch(
					actListTarg, this.isMustBePresent());
			if (actionMatch == null)
				actionMatch = new ArrayList<ActionMatch>();

			if (this.selectedMatchId != null && matchIds != null) {
				if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {

					this.setOperationFail(false);
					daoTarget.updateTargetActions(selectedTarget.getPkTarget(),
							actionMatch);
					log.info("Closing dialog.");
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
					this.matchIds = null;
					this.mustBePresent = false;
				} else
					context.execute("noMatchIdDialoga.show()");
			} else {
				context.execute("noMatchIdDialoga.show()");
			}
		}

	}

	/**
	 * Saves the newly added instance of {@code Environments} corresponding to
	 * an existing {@code Target} instance in the database.
	 * 
	 */
	public void saveUpdatedTargetEnvironment() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (selectedTarget != null) {
			envListTarg = addForEnvironmentMatch();
			if (envListTarg == null)
				envListTarg = new ArrayList<Object[]>();

			List<EnvironmentMatch> environmentMatch = daoTarget
					.createEnvironmentMatch(envListTarg, this.isMustBePresent());
			if (environmentMatch == null)
				environmentMatch = new ArrayList<EnvironmentMatch>();
			if (this.selectedMatchId != null && matchIds != null) {
				if (matchIds.size() > 0 && this.selectedMatchId.length() > 0) {
					this.setOperationFail(false);
					daoTarget.updateTargetEnvironments(
							selectedTarget.getPkTarget(), environmentMatch);
					log.info("Closing dialog.");
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
					this.matchIds = null;
					this.mustBePresent = false;
				} else
					context.execute("noMatchIdDialoge.show()");
			} else {
				context.execute("noMatchIdDialoge.show()");
			}

		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

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

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns the next step {@code String}.Used in Primefaces {@code wizard}
	 * component for going to next step of the wizard.
	 * 
	 * @param event
	 * @return nextStep
	 */
	public String onFlowProcess(FlowEvent event) {
		return event.getNewStep();

	}

}
