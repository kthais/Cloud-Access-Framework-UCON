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

package com.aislab.accesscontrol.core.ui.dao;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

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
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Targets
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class TargetDAO {

	/**
	 * A SessionFactory variable to configure the database session
	 */
	public static SessionFactory sessionFactory;

	/**
	 * A Session variable to store the session opened
	 */
	public static Session session;

	/**
	 * A Transaction variable used to start a transaction in a session
	 */
	public static Transaction tx;

	/**
	 * A Query variable used to retrieve information from database
	 */
	Query query;

	public TargetDAO() {
		sessionFactory = HibernateUtil.configureSessionFactory();
	}

	/**
	 * Returns Subject Attributes of the given Subject added to the Target
	 * 
	 * @param subject
	 * @return
	 */
	public SubjectAttribute getRequiredSubjectArrtibute(Subjects subject) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		SubjectAttribute subAttr;
		SubjectMatch subMatch;
		SubAttrValues subAttrValues;
		subMatch = subject.getSubjectMatch();
		session.update(subMatch);
		subAttrValues = subMatch.getSubAttrValues();
		session.update(subAttrValues);
		subAttr = subAttrValues.getSubjectAttribute();

		session.close();
		return subAttr;
	}

	/**
	 * Returns Subject Attributes Values of the given Subject added to the
	 * Target
	 * 
	 * @param subject
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public SubAttrValues getRequiredSubjectAttributeValue(Subjects subject) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<SubjectMatch> subMList = (List<SubjectMatch>) session.createQuery(
				"select s.subjectMatch from Subjects s where s.pkSubjects="
						+ subject.getPkSubjects()).list();
		Iterator<SubjectMatch> subMIter = subMList.iterator();

		SubjectMatch subMatch = null;
		if (subMIter.hasNext())
			subMatch = (SubjectMatch) subMIter.next();
		SubAttrValues subAttrValue = null;
		List<SubAttrValues> subAValues = (List<SubAttrValues>) session
				.createQuery(
						"select sm.subAttrValues from SubjectMatch sm where sm.pkSubjMatch="
								+ subMatch.getPkSubjMatch()).list();
		Iterator<SubAttrValues> subVIter = subAValues.iterator();
		if (subVIter.hasNext())
			subAttrValue = (SubAttrValues) subVIter.next();

		if (session.isOpen())
			session.close();
		tx.commit();
		return subAttrValue;
	}

	/**
	 * Returns Resource Attributes Values of the given Resource added to the
	 * Target
	 * 
	 * @param resource
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public ResAttrValues getRequiredResourceAttributeValue(Resources resource) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ResourceMatch> resMList = (List<ResourceMatch>) session
				.createQuery(
						"select r.resourceMatch from Resources r where r.pkResources="
								+ resource.getPkResources()).list();
		Iterator<ResourceMatch> resMIter = resMList.iterator();

		ResourceMatch resMatch = null;
		if (resMIter.hasNext())
			resMatch = (ResourceMatch) resMIter.next();
		ResAttrValues resAttrValue = null;
		List<ResAttrValues> resAValues = (List<ResAttrValues>) session
				.createQuery(
						"select sm.resAttrValues from ResourceMatch sm where sm.pkResMatch="
								+ resMatch.getPkResMatch()).list();
		Iterator<ResAttrValues> resVIter = resAValues.iterator();
		if (resVIter.hasNext())
			resAttrValue = (ResAttrValues) resVIter.next();

		if (session.isOpen())
			session.close();
		tx.commit();
		return resAttrValue;

	}

	/**
	 * Returns List of Primary Keys of Resource Matches for the given resource
	 * added to the target
	 * 
	 * @param resource
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Long> getPkMatch(Resources resource) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ResourceMatch> resMList = (List<ResourceMatch>) session
				.createQuery(
						"select s.resourceMatch from Resources s where s.pkResources="
								+ resource.getPkResources()).list();
		Iterator<ResourceMatch> resMIter = resMList.iterator();

		ResourceMatch resMatch = null;
		if (resMIter.hasNext())
			resMatch = (ResourceMatch) resMIter.next();

		List<Long> mIds = (List<Long>) session.createQuery(
				"select sm.pkResMatch from ResourceMatch sm where sm.pkResMatch="
						+ resMatch.getPkResMatch()).list();

		return mIds;
	}

	/**
	 * Returns Match Id of the Resource Match for the given resource added to
	 * the target
	 * 
	 * @param resource
	 * @return
	 */

	@SuppressWarnings("unchecked")
	public String getMatchId(Resources resource) {
		String matchId = null;
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ResourceMatch> resMList = (List<ResourceMatch>) session
				.createQuery(
						"select s.resourceMatch from Resources s where s.pkResources="
								+ resource.getPkResources()).list();
		Iterator<ResourceMatch> resMIter = resMList.iterator();

		ResourceMatch resMatch = null;
		if (resMIter.hasNext())
			resMatch = (ResourceMatch) resMIter.next();
		List<String> mIds = (List<String>) session.createQuery(
				"select sm.matchId from ResourceMatch sm where sm.pkResMatch="
						+ resMatch.getPkResMatch()).list();
		Iterator<String> iterMid = mIds.iterator();
		if (iterMid.hasNext())
			matchId = (String) iterMid.next();
		return matchId;
	}

	/**
	 * Returns Match Id of the Subject Match for the given subject added to the
	 * target
	 * 
	 * @param subject
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public String getMatchId(Subjects subject) {
		String matchId = null;
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<SubjectMatch> subMList = (List<SubjectMatch>) session.createQuery(
				"select s.subjectMatch from Subjects s where s.pkSubjects="
						+ subject.getPkSubjects()).list();
		Iterator<SubjectMatch> subMIter = subMList.iterator();

		SubjectMatch subMatch = null;
		if (subMIter.hasNext())
			subMatch = (SubjectMatch) subMIter.next();
		List<String> mIds = (List<String>) session.createQuery(
				"select sm.matchId from SubjectMatch sm where sm.pkSubjMatch="
						+ subMatch.getPkSubjMatch()).list();
		Iterator<String> iterMid = mIds.iterator();
		if (iterMid.hasNext())
			matchId = (String) iterMid.next();
		return matchId;
	}

	/**
	 * Returns list of All Targets
	 * 
	 * @return
	 */

	@SuppressWarnings("unchecked")
	public List<Target> selectTarget() {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Target");
		List<Target> targets = query.list();
		tx.commit();
		session.close();
		return targets;
	}

	/**
	 * Returns List of Subjects of a Target with the given Primary Key
	 * 
	 * @param pkTarget
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Subjects> populateTargetSubjects(Long pkTarget) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Subjects> subs = (List<Subjects>) session.createQuery(
				"select t.subjects from Target t where t.pkTarget = "
						+ pkTarget).list();
		tx.commit();
		session.close();
		return subs;
	}

	/**
	 * Returns List of Resources of a Target with the given Primary Key
	 * 
	 * @param pkTarget
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Resources> populateTargetSubjectsResources(Long pkTarget) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Resources> res = (List<Resources>) session.createQuery(
				"select t.resources from Target t " + "where t.pkTarget = "
						+ pkTarget).list();
		tx.commit();
		session.close();
		return res;
	}

	/**
	 * Returns List of Actions of a Target with the given Primary Key
	 * 
	 * @param pkTarget
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Actions> populateTargetActions(Long pkTarget) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Actions> acts = (List<Actions>) session.createQuery(
				"select t.actions from Target t " + "where t.pkTarget = "
						+ pkTarget).list();
		tx.commit();
		session.close();
		return acts;
	}

	/**
	 * Returns List of Environments of a Target with the given Primary Key
	 * 
	 * @param pkTarget
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<Environments> populateTargetEnvironments(Long pkTarget) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Environments> envs = (List<Environments>) session.createQuery(
				"select t.environments from Target t " + "where t.pkTarget = "
						+ pkTarget).list();
		tx.commit();
		session.close();
		return envs;
	}

	/**
	 * Creates and Returns List of Subject Matches for the given Objects List
	 * for updating Target
	 * 
	 * @param list
	 * @return
	 */

	public List<SubjectMatch> createSubjectMatchForUpdate(List<Object[]> list,
			boolean mustBePresent) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<SubjectMatch> subMatchList = new ArrayList<SubjectMatch>();
		SubjectMatch subMatch;
		if (list == null)
			list = new ArrayList<Object[]>();
		for (Object[] obj : list) {
			subMatch = new SubjectMatch((SubAttrValues) obj[0], (String) obj[1]);
			subMatch.setMustBePresent(mustBePresent);
			subMatchList.add(subMatch);

		}
		tx.commit();
		session.close();
		return subMatchList;
	}

	/**
	 * Creates and Returns List of Subject Matches for the given Objects List
	 * needed for creating Target
	 * 
	 * @param list
	 * @return
	 */
	public List<SubjectMatch> createSubjectMatch(List<Object[]> list,
			boolean mustBePresent) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<SubjectMatch> subMatchList = new ArrayList<SubjectMatch>();
		SubjectMatch subMatch;
		if (list == null)
			list = new ArrayList<Object[]>();
		for (Object[] obj : list) {
			subMatch = new SubjectMatch((SubAttrValues) obj[0], (String) obj[1]);
			subMatch.setMustBePresent(mustBePresent);
			subMatchList.add(subMatch);

			session.persist(subMatch);
		}
		tx.commit();
		session.close();
		return subMatchList;
	}

	/**
	 * Creates and Returns List of Resource Matches for the given Objects List
	 * needed for creating Target
	 * 
	 * @param list
	 * @return
	 */
	public List<ResourceMatch> createResourceMatch(List<Object[]> list,
			boolean mustBePresent) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ResourceMatch> resMatchList = new ArrayList<ResourceMatch>();
		ResourceMatch resMatch;
		if (list == null)
			list = new ArrayList<Object[]>();
		for (Object[] obj : list) {
			resMatch = new ResourceMatch((ResAttrValues) obj[0],
					(String) obj[1]);
			resMatch.setMustBePresent(mustBePresent);
			resMatchList.add(resMatch);

			session.persist(resMatch);
		}
		tx.commit();
		session.close();
		return resMatchList;
	}

	/**
	 * Creates and Returns List of Action Matches for the given Objects List
	 * needed for creating Target
	 * 
	 * @param list
	 * @return
	 */
	public List<ActionMatch> createActionMatch(List<Object[]> list,
			boolean mustBePresent) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ActionMatch> actMatchList = new ArrayList<ActionMatch>();
		ActionMatch actMatch;
		if (list == null)
			list = new ArrayList<Object[]>();
		for (Object[] obj : list) {
			actMatch = new ActionMatch((ActAttrValues) obj[0], (String) obj[1]);
			actMatch.setMustBePresent(mustBePresent);
			actMatchList.add(actMatch);

			session.persist(actMatch);
		}
		tx.commit();
		session.close();
		return actMatchList;
	}

	/**
	 * Creates and Returns List of Environment Matches for the given Objects
	 * List needed for creating Target
	 * 
	 * @param list
	 * @return
	 */
	public List<EnvironmentMatch> createEnvironmentMatch(List<Object[]> list,
			boolean mustBePresent) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<EnvironmentMatch> envMatchList = new ArrayList<EnvironmentMatch>();
		EnvironmentMatch envMatch;
		if (list == null)
			list = new ArrayList<Object[]>();
		for (Object[] obj : list) {
			envMatch = new EnvironmentMatch((EnvAttrValues) obj[0],
					(String) obj[1]);
			envMatch.setMustBePresent(mustBePresent);

			envMatchList.add(envMatch);
			session.persist(envMatch);
		}
		tx.commit();
		session.close();
		return envMatchList;
	}

	/**
	 * Called By create Target function for creating new Target and setting its
	 * parameters
	 * 
	 * @param target
	 * @param description
	 * @param subMatchList
	 * @param actMatchList
	 * @param resMatchList
	 * @param envMatchList
	 */
	public void setTargetParameters(Target target, String targetId,
			String description, List<SubjectMatch> subMatchList,
			List<ActionMatch> actMatchList, List<ResourceMatch> resMatchList,
			List<EnvironmentMatch> envMatchList) {

		tx = session.beginTransaction();
		Set<Subjects> subSet;
		Subjects subs;
		Set<Actions> actSet;
		Actions acts;
		Set<Resources> resSet;
		Resources ress;
		Set<Environments> envSet;
		Environments envs;

		// Add Subjects into Target
		if (!subMatchList.isEmpty()) {
			subSet = new HashSet<Subjects>(0);
			SubjectAttribute attr;
			for (SubjectMatch sm : subMatchList) {
				attr = sm.getSubAttrValues().getSubjectAttribute();

				session.update(attr);
				subs = new Subjects(attr.getSubject(), sm);
				session.persist(subs);
				subSet.add(subs);
			}
			target.setSubjects(subSet);
		}

		// Add Actions into Target
		if (!actMatchList.isEmpty()) {
			ActionAttribute attr;
			actSet = new HashSet<Actions>(0);
			for (ActionMatch am : actMatchList) {
				attr = am.getActAttrValues().getActionAttribute();
				session.update(attr);
				acts = new Actions(attr.getAction(), am);
				session.persist(acts);
				actSet.add(acts);
			}
			target.setActions(actSet);
		}

		// Add Resources into Target
		if (!resMatchList.isEmpty()) {
			ResourceAttribute attr;
			resSet = new HashSet<Resources>(0);
			for (ResourceMatch rm : resMatchList) {
				attr = rm.getResAttrValues().getResourceAttribute();
				session.update(attr);
				ress = new Resources(attr.getResource(), rm);
				session.persist(ress);
				resSet.add(ress);
			}

			target.setResources(resSet);
		}

		// Add Environments to Target
		if (!envMatchList.isEmpty()) {
			EnvironmentAttribute attr;
			envSet = new HashSet<Environments>(0);
			for (EnvironmentMatch em : envMatchList) {
				attr = em.getEnvAttrValues().getEnvironmentAttribute();
				session.update(attr);
				envs = new Environments(attr.getEnvironment(), em);
				session.persist(envs);
				envSet.add(envs);
			}

			target.setEnvironments(envSet);
		}
		target.setDescription(description);
		target.setTargetId(targetId);
		tx.commit();

	}

	public Target createTarget(String targetId, String description,
			List<SubjectMatch> subMatchList, List<ActionMatch> actMatchList,
			List<ResourceMatch> resMatchList,
			List<EnvironmentMatch> envMatchList) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();

		Target targ = new Target();
		targ.setDescription(description);
		setTargetParameters(targ, targetId, description, subMatchList,
				actMatchList, resMatchList, envMatchList);
		/*
		 * Once all Subjects, Actions, Resources and Environments have been
		 * added to the Target, it needs to be saved into the database.
		 */
		tx = session.beginTransaction();

		session.persist(targ);
		tx.commit();
		session.close();
		return targ;

	}

	/**
	 * Deletes Target with the primary Key pkTarget
	 * 
	 * @param pkTarget
	 */
	public void deleteTarget(Long pkTarget) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		session.delete(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Updates Target with the primary key pkTarget with the given parameters
	 * 
	 * @param pkTarget
	 * @param description
	 * @param subMatchList
	 * @param actMatchList
	 * @param resMatchList
	 * @param envMatchList
	 */

	public void updateTarget(Long pkTarget, String targetId,
			String description, List<SubjectMatch> subMatchList,
			List<ActionMatch> actMatchList, List<ResourceMatch> resMatchList,
			List<EnvironmentMatch> envMatchList) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		tx.commit();
		setTargetParameters(targ, targetId, description, subMatchList,
				actMatchList, resMatchList, envMatchList);
		session.update(targ);

		tx.commit();
		session.close();

	}

	/**
	 * Updates Target with the primary key pkTarget with the given parameters
	 * 
	 * @param pkTarget
	 * @param description
	 */
	public void updateTarget(Long pkTarget, String targetId, String description) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		targ.setDescription(description);
		targ.setTargetId(targetId);
		session.update(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Updates Target with the primary key pkTarget with the given list of
	 * Subject Matches
	 * 
	 * @param pkTarget
	 * @param subMatchList
	 */
	public void updateTargetSubjects(Long pkTarget,
			List<SubjectMatch> subMatchList) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		Set<Subjects> subSet;
		Subjects subs;
		if (!subMatchList.isEmpty()) {

			subSet = new HashSet<Subjects>(0);
			SubjectAttribute attr;
			for (SubjectMatch sm : subMatchList) {
				attr = sm.getSubAttrValues().getSubjectAttribute();

				session.update(attr);
				subs = new Subjects(attr.getSubject(), sm);

				System.out
						.println("Attribute Subject is :" + attr.getSubject());
				session.persist(subs);
				subSet.add(subs);
				targ.setSubjects(subSet);
				session.update(targ);
			}

			tx.commit();
			session.close();
		}

	}

	/**
	 * Updates Target with the primary key pkTarget with the given list of
	 * Resource Matches
	 * 
	 * @param pkTarget
	 * @param resMatchList
	 */
	public void updateTargetResources(Long pkTarget,
			List<ResourceMatch> resMatchList) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Set<Resources> resSet;
		Resources ress;
		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();

		if (!resMatchList.isEmpty()) {
			ResourceAttribute attr;
			resSet = new HashSet<Resources>(0);
			for (ResourceMatch rm : resMatchList) {
				attr = rm.getResAttrValues().getResourceAttribute();
				session.update(attr);
				ress = new Resources(attr.getResource(), rm);
				session.persist(ress);
				resSet.add(ress);
			}

			targ.setResources(resSet);
			session.update(targ);
			tx.commit();
			session.close();
		}

	}

	/**
	 * Returns Action Attribute Values for the Actions given that are added to
	 * the Target
	 * 
	 * @param acts
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public ActAttrValues getRequiredActionAttributeValue(Actions acts) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ActionMatch> actMList = (List<ActionMatch>) session.createQuery(
				"select s.actionMatch from Actions s where s.pkActions="
						+ acts.getPkActions()).list();
		Iterator<ActionMatch> actMIter = actMList.iterator();

		ActionMatch actMatch = null;
		if (actMIter.hasNext())
			actMatch = (ActionMatch) actMIter.next();
		ActAttrValues actAttrValue = null;
		List<ActAttrValues> actAValues = (List<ActAttrValues>) session
				.createQuery(
						"select sm.actAttrValues from ActionMatch sm where sm.pkActMatch="
								+ actMatch.getPkActMatch()).list();
		Iterator<ActAttrValues> actVIter = actAValues.iterator();
		if (actVIter.hasNext())
			actAttrValue = (ActAttrValues) actVIter.next();

		if (session.isOpen())
			session.close();
		tx.commit();
		return actAttrValue;
	}

	/**
	 * Returns MatchId for the Actions given that are added to the Target
	 * 
	 * @param acts
	 * @return
	 */

	@SuppressWarnings("unchecked")
	public String getMatchId(Actions acts) {
		String matchId = null;
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<ActionMatch> actMList = (List<ActionMatch>) session.createQuery(
				"select s.actionMatch from Actions s where s.pkActions="
						+ acts.getPkActions()).list();
		Iterator<ActionMatch> actMIter = actMList.iterator();

		ActionMatch actMatch = null;
		if (actMIter.hasNext())
			actMatch = (ActionMatch) actMIter.next();
		List<String> mIds = (List<String>) session.createQuery(
				"select sm.matchId from ActionMatch sm where sm.pkActMatch="
						+ actMatch.getPkActMatch()).list();
		Iterator<String> iterMid = mIds.iterator();
		if (iterMid.hasNext())
			matchId = (String) iterMid.next();
		return matchId;
	}

	/**
	 * Deletes the given Subject in the Target with primaryKey pkTarget on basis
	 * of subject Match
	 * 
	 * @param pkTarget
	 * @param subject
	 * @param subj
	 */
	@SuppressWarnings("unchecked")
	public void deleteSubject(Long pkTarget, Subjects subject, Subject subj) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		List<Subjects> subSet = (List<Subjects>) session.createQuery(
				"from Subjects s join fetch s.targets t where t.pkTarget = "
						+ pkTarget).list();

		Subject sub;

		for (int r = 0; r < subSet.size(); r++) {
			Subjects s = (Subjects) subSet.get(r);
			sub = (Subject) session.createQuery(
					"from Subject sb join fetch sb.subjects ss where ss.pkSubjects = "
							+ s.getPkSubjects()).uniqueResult();

			if (sub.getPkSubject() == subj.getPkSubject()) {
				Query query = session
						.createQuery("select sub.subjectMatch from Target t join t.subjects sub where t.pkTarget = "
								+ pkTarget
								+ " and sub.pkSubjects ="
								+ subject.getPkSubjects());
				SubjectMatch subM = (SubjectMatch) query.uniqueResult();
				SubjectMatch sM = (SubjectMatch) session.createQuery(
						"select sub.subjectMatch from Target t join t.subjects sub where t.pkTarget = "
								+ pkTarget + " and sub.pkSubjects ="
								+ s.getPkSubjects()).uniqueResult();
				if (subM.getPkSubjMatch() == sM.getPkSubjMatch())
					subSet.remove(r);
			}
		}
		Set<Subjects> updatedSubjects = new HashSet<Subjects>();
		for (int r = 0; r < subSet.size(); r++) {
			updatedSubjects.add(subSet.get(r));
		}
		targ.setSubjects(updatedSubjects);
		session.update(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Returns Environment Attribute Values of the environments object passed to
	 * the function added to a Target
	 * 
	 * @param environment
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public EnvAttrValues getRequiredEnvironmentAttributeValue(
			Environments environment) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<EnvironmentMatch> envMList = (List<EnvironmentMatch>) session
				.createQuery(
						"select s.environmentMatch from Environments s where s.pkEnvironments="
								+ environment.getPkEnvironments()).list();
		Iterator<EnvironmentMatch> envMIter = envMList.iterator();

		EnvironmentMatch envMatch = null;
		if (envMIter.hasNext())
			envMatch = (EnvironmentMatch) envMIter.next();
		EnvAttrValues envAttrValue = null;
		List<EnvAttrValues> envAValues = (List<EnvAttrValues>) session
				.createQuery(
						"select sm.envAttrValues from EnvironmentMatch sm where sm.pkEnvMatch="
								+ envMatch.getPkEnvMatch()).list();
		Iterator<EnvAttrValues> envVIter = envAValues.iterator();
		if (envVIter.hasNext())
			envAttrValue = (EnvAttrValues) envVIter.next();

		if (session.isOpen())
			session.close();
		tx.commit();
		return envAttrValue;
	}

	/**
	 * Returns Match Id of the Environments Object added to a Target on basis of
	 * Environment Match
	 * 
	 * @param environment
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public String getMatchId(Environments environment) {
		String matchId = null;
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<EnvironmentMatch> envMList = (List<EnvironmentMatch>) session
				.createQuery(
						"select s.environmentMatch from Environments s where s.pkEnvironments="
								+ environment.getPkEnvironments()).list();
		Iterator<EnvironmentMatch> envMIter = envMList.iterator();

		EnvironmentMatch envMatch = null;
		if (envMIter.hasNext())
			envMatch = (EnvironmentMatch) envMIter.next();
		List<String> mIds = (List<String>) session.createQuery(
				"select sm.matchId from EnvironmentMatch sm where sm.pkEnvMatch="
						+ envMatch.getPkEnvMatch()).list();
		Iterator<String> iterMid = mIds.iterator();
		if (iterMid.hasNext())
			matchId = (String) iterMid.next();
		return matchId;
	}

	/**
	 * Returns Subject Class Object from the Subjects Class Object using
	 * subjectMatch of a given Target
	 * 
	 * @param pkTarget
	 * @param subjects
	 * @param subjectMatch
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Subject getSubjectFromSubjects(Long pkTarget, Subjects subjects,
			List<SubjectMatch> subjectMatch) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Subject sub = null;

		List<Subjects> subSet = (List<Subjects>) session.createQuery(
				"from Subjects s join fetch s.targets t where t.pkTarget = "
						+ pkTarget).list();
		SubjectAttribute attr;
		for (SubjectMatch sm : subjectMatch) {
			attr = sm.getSubAttrValues().getSubjectAttribute();

			sub = attr.getSubject();

		}
		Query query = session
				.createQuery("select sub.subjectMatch from Target t join t.subjects sub where t.pkTarget = "
						+ pkTarget
						+ " and sub.pkSubjects ="
						+ subjects.getPkSubjects());
		SubjectMatch subM = (SubjectMatch) query.uniqueResult();
		for (Subjects s : subSet) {
			if (s.getPkSubjects() == subjects.getPkSubjects()) {
				sub = (Subject) session.createQuery(
						"from Subject sb join fetch sb.subjects ss where ss.pkSubjects = "
								+ s.getPkSubjects()).uniqueResult();

				break;
			}
		}

		if (subM != null) {
			SubAttrValues sValues = (SubAttrValues) session
					.createQuery(
							"from SubAttrValues sv join fetch sv.subjectMatches sms where sms.pkSubjMatch = "
									+ subM.getPkSubjMatch()).uniqueResult();
			SubjectAttribute subjecA = sValues.getSubjectAttribute();
			Subject s = (Subject) session.createQuery(
					"from Subject s join fetch s.subjectAttributes sa where sa.pkSubAttr = "
							+ subjecA.getPkSubAttr()).uniqueResult();
			tx.commit();
			session.close();
			return s;

		}
		return sub;
	}

	/**
	 * Returns Resource Class Object from the Resources Class Object using
	 * resourceMatch of a given Target
	 * 
	 * @param pkTarget
	 * @param resources
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Resource getResourceFromResources(Long pkTarget, Resources resources) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Resource res = null;

		List<Resources> subSet = (List<Resources>) session.createQuery(
				"from Resources r join fetch r.targets t where t.pkTarget = "
						+ pkTarget).list();
		for (Resources r : subSet) {
			if (r.getPkResources() == resources.getPkResources()) {
				res = (Resource) session.createQuery(
						"from Resource rb join fetch rb.resources rs where rs.pkResources = "
								+ r.getPkResources()).uniqueResult();
				break;

			}
		}
		Query query = session
				.createQuery("select res.resourceMatch from Target t join t.resources res where t.pkTarget = "
						+ pkTarget
						+ " and res.pkResources ="
						+ resources.getPkResources());
		ResourceMatch resM = (ResourceMatch) query.uniqueResult();

		if (resM != null) {
			ResAttrValues rValues = (ResAttrValues) session
					.createQuery(
							"from ResAttrValues sv join fetch sv.resourceMatches sms where sms.pkResMatch = "
									+ resM.getPkResMatch()).uniqueResult();
			ResourceAttribute subjecA = rValues.getResourceAttribute();
			Resource r = (Resource) session.createQuery(
					"from Resource s join fetch s.resourceAttributes sa where sa.pkResAttr = "
							+ subjecA.getPkResAttr()).uniqueResult();
			tx.commit();
			session.close();
			return r;

		}
		tx.commit();
		session.close();
		return res;
	}

	/**
	 * Deletes the given Resource from the given Target Primary Key
	 * 
	 * @param pkTarget
	 * @param resource
	 * @param re
	 */
	@SuppressWarnings("unchecked")
	public void deleteResource(Long pkTarget, Resources resource, Resource re) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		List<Resources> subSet = (List<Resources>) session.createQuery(
				"from Resources r join fetch r.targets t where t.pkTarget = "
						+ pkTarget).list();

		Resource res;
		for (int r = 0; r < subSet.size(); r++) {
			Resources rs = (Resources) subSet.get(r);
			res = (Resource) session.createQuery(
					"from Resource rb join fetch rb.resources rs where rs.pkResources = "
							+ rs.getPkResources()).uniqueResult();

			if ((res.getPkResource() == re.getPkResource())) {
				Query query = session
						.createQuery("select res.resourceMatch from Target t join t.resources res where t.pkTarget = "
								+ pkTarget
								+ " and res.pkResources ="
								+ resource.getPkResources());
				ResourceMatch resM = (ResourceMatch) query.uniqueResult();
				ResourceMatch rM = (ResourceMatch) session
						.createQuery(
								"select res.resourceMatch from Target t join t.resources res where t.pkTarget = "
										+ pkTarget
										+ " and res.pkResources ="
										+ rs.getPkResources()).uniqueResult();
				if (rM.getPkResMatch() == resM.getPkResMatch())
					subSet.remove(r);
			}
		}

		Set<Resources> updatedResources = new HashSet<Resources>();
		for (int r = 0; r < subSet.size(); r++) {
			updatedResources.add(subSet.get(r));
		}
		targ.setResources(updatedResources);
		session.update(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Returns Action Class Object from the Actions Class Object using
	 * actionMatch of a given Target
	 * 
	 * @param pkTarget
	 * @param actions
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Action getActionFromActions(Long pkTarget, Actions actions) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Action act = null;
		List<Actions> subSet = (List<Actions>) session.createQuery(
				"from Actions r join fetch r.targets t where t.pkTarget = "
						+ pkTarget).list();
		for (Actions a : subSet) {
			if (a.getPkActions() == actions.getPkActions()) {
				act = (Action) session.createQuery(
						"from Action a join fetch a.actions acts where acts.pkActions = "
								+ a.getPkActions()).uniqueResult();
				break;

			}
		}
		Query query = session
				.createQuery("select act.actionMatch from Target t join t.actions act where t.pkTarget = "
						+ pkTarget
						+ " and act.pkActions ="
						+ actions.getPkActions());
		ActionMatch actM = (ActionMatch) query.uniqueResult();

		if (actM != null) {

			ActAttrValues aValues = (ActAttrValues) session.createQuery(
					"from ActAttrValues sv join fetch sv.actionMatches sms where sms.pkActMatch = "
							+ actM.getPkActMatch()).uniqueResult();
			ActionAttribute aa = aValues.getActionAttribute();
			Action a = (Action) session.createQuery(
					"from Action s join fetch s.actionAttributes sa where sa.pkActAttr = "
							+ aa.getPkActAttr()).uniqueResult();
			tx.commit();
			session.close();
			return a;

		}
		tx.commit();
		session.close();
		return act;
	}

	/**
	 * Deletes given Action from the given Target with the primary key pkTarget
	 * 
	 * @param pkTarget
	 * @param actions
	 * @param a
	 */
	@SuppressWarnings("unchecked")
	public void deleteAction(Long pkTarget, Actions actions, Action a) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		List<Actions> subSet = (List<Actions>) session.createQuery(
				"from Actions a join fetch a.targets t where t.pkTarget = "
						+ pkTarget).list();
		Action act;

		for (int r = 0; r < subSet.size(); r++) {
			Actions as = (Actions) subSet.get(r);
			act = (Action) session.createQuery(
					"from Action a join fetch a.actions acts where acts.pkActions = "
							+ as.getPkActions()).uniqueResult();

			if (act.getPkAction() == a.getPkAction()) {
				Query query = session
						.createQuery("select act.actionMatch from Target t join t.actions act where t.pkTarget = "
								+ pkTarget
								+ " and act.pkActions ="
								+ actions.getPkActions());
				ActionMatch actM = (ActionMatch) query.uniqueResult();
				ActionMatch aM = (ActionMatch) session.createQuery(
						"select act.actionMatch from Target t join t.actions act where t.pkTarget = "
								+ pkTarget + " and act.pkActions ="
								+ as.getPkActions()).uniqueResult();
				if (actM.getPkActMatch() == aM.getPkActMatch())
					subSet.remove(r);
			}
		}
		Set<Actions> updatedActions = new HashSet<Actions>();
		for (int r = 0; r < subSet.size(); r++) {
			updatedActions.add(subSet.get(r));
		}
		targ.setActions(updatedActions);
		session.update(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Updates Target Action with the given actionMatchList
	 * 
	 * @param pkTarget
	 * @param actMatchList
	 */
	public void updateTargetActions(Long pkTarget,
			List<ActionMatch> actMatchList) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Set<Actions> actSet;
		Actions acts;
		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();

		if (!actMatchList.isEmpty()) {
			ActionAttribute attr;
			actSet = new HashSet<Actions>(0);
			for (ActionMatch am : actMatchList) {
				attr = am.getActAttrValues().getActionAttribute();
				session.update(attr);
				acts = new Actions(attr.getAction(), am);
				session.persist(acts);
				actSet.add(acts);
			}
			targ.setActions(actSet);
			session.update(targ);
			tx.commit();
			session.close();
		}
	}

	/**
	 * Updates Target Environment with the given environmentMatchList
	 * 
	 * @param pkTarget
	 * @param envMatchList
	 */
	public void updateTargetEnvironments(Long pkTarget,
			List<EnvironmentMatch> envMatchList) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Set<Environments> envSet;
		Environments envs;
		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		if (!envMatchList.isEmpty()) {
			EnvironmentAttribute attr;
			envSet = new HashSet<Environments>(0);
			for (EnvironmentMatch em : envMatchList) {
				attr = em.getEnvAttrValues().getEnvironmentAttribute();
				session.update(attr);
				envs = new Environments(attr.getEnvironment(), em);
				session.persist(envs);
				envSet.add(envs);
			}

			targ.setEnvironments(envSet);
			session.update(targ);
			tx.commit();
			session.close();
		}
	}

	/**
	 * Deletes Environment object reference passed to the function from the
	 * given Target referenced from primary key pkTarget
	 * 
	 * @param pkTarget
	 * @param environments
	 * @param en
	 */
	@SuppressWarnings("unchecked")
	public void deleteEnvironment(Long pkTarget, Environments environments,
			Environment en) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Target targ = (Target) session.createQuery(
				"from Target t where t.pkTarget = " + pkTarget).uniqueResult();
		List<Environments> subSet = (List<Environments>) session.createQuery(
				"from Environments a join fetch a.targets t where t.pkTarget = "
						+ pkTarget).list();
		Environment env;
		for (int r = 0; r < subSet.size(); r++) {
			Environments as = (Environments) subSet.get(r);
			env = (Environment) session
					.createQuery(
							"from Environment a join fetch a.environments acts where acts.pkEnvironments = "
									+ as.getPkEnvironments()).uniqueResult();

			if (env.getPkEnvironment() == en.getPkEnvironment()) {
				Query query = session
						.createQuery("select sub.environmentMatch from Target t join t.environments sub where t.pkTarget = "
								+ pkTarget
								+ " and sub.pkEnvironments ="
								+ environments.getPkEnvironments());
				EnvironmentMatch envM = (EnvironmentMatch) query.uniqueResult();
				EnvironmentMatch eM = (EnvironmentMatch) session
						.createQuery(
								"select sub.environmentMatch from Target t join t.environments sub where t.pkTarget = "
										+ pkTarget
										+ " and sub.pkEnvironments ="
										+ as.getPkEnvironments())
						.uniqueResult();
				if (envM.getPkEnvMatch() == eM.getPkEnvMatch())
					subSet.remove(r);
			}
		}
		Set<Environments> updatedEnvironments = new HashSet<Environments>();
		for (int r = 0; r < subSet.size(); r++) {
			updatedEnvironments.add(subSet.get(r));
		}
		targ.setEnvironments(updatedEnvironments);
		session.update(targ);
		tx.commit();
		session.close();
	}

	/**
	 * Returns Environment Class Object from the Environments Class Object using
	 * environmentMatch of a given Target
	 * 
	 * @param pkTarget
	 * @param environments
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public Environment getEnvironmentByEnvironments(Long pkTarget,
			Environments environments) {
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Environment env = null;
		List<Environments> subSet = (List<Environments>) session.createQuery(
				"from Environments r join fetch r.targets t where t.pkTarget = "
						+ pkTarget).list();
		for (Environments a : subSet) {
			if (a.getPkEnvironments() == environments.getPkEnvironments()) {
				env = (Environment) session
						.createQuery(
								"from Environment a join fetch a.environments acts where acts.pkEnvironments = "
										+ a.getPkEnvironments()).uniqueResult();
				break;

			}
		}
		Query query = session
				.createQuery("select env.environmentMatch from Target t join t.environments env where t.pkTarget = "
						+ pkTarget
						+ " and env.pkEnvironments ="
						+ environments.getPkEnvironments());
		EnvironmentMatch envM = (EnvironmentMatch) query.uniqueResult();

		if (envM != null) {
			EnvAttrValues eValues = (EnvAttrValues) session
					.createQuery(
							"from EnvAttrValues sv join fetch sv.environmentMatches sms where sms.pkEnvMatch = "
									+ envM.getPkEnvMatch()).uniqueResult();
			EnvironmentAttribute aa = eValues.getEnvironmentAttribute();
			Environment a = (Environment) session
					.createQuery(
							"from Environment s join fetch s.environmentAttributes sa where sa.pkEnvAttr = "
									+ aa.getPkEnvAttr()).uniqueResult();
			tx.commit();
			session.close();
			return a;

		}
		tx.commit();
		session.close();
		return env;
	}

	/**
	 * Returns DataTpye of the subject attribute value using value of the
	 * attribute as parameter
	 * 
	 * @param sValue
	 * 
	 * @return
	 */

	public String getSubjectAttributeDataType(SubAttrValues sValue) {

		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		SubjectAttribute subAtt = (SubjectAttribute) session
				.createQuery(
						"from SubjectAttribute s join fetch s.subAttrValues sv where sv.pkSubAttrVal = "
								+ sValue.getSubAttrValue()).uniqueResult();
		String dataType = (String) session.createQuery(
				"select sa.dataType from SubjectAttribute sa where sa.pkSubAttr = "
						+ subAtt.getPkSubAttr()).uniqueResult();
		return dataType;
	}

	/**
	 * Returns MatchId and Value of the subject using subject value as parameter
	 * 
	 * @param subs
	 * 
	 * @return
	 */

	public String getMatchIdAndValue(Subjects subs) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Object[] res = (Object[]) session
				.createQuery(
						"select sm.matchId, val.subAttrValue from Subjects s join s.subjectMatch sm join sm.subAttrValues val where s.pkSubjects = "
								+ subs.getPkSubjects()).uniqueResult();

		String matchId = res[0].toString() + " ";
		String value = res[1].toString();
		String[] splittedMatchId = matchId.split(":");
		tx.commit();
		session.close();
		if (splittedMatchId.length < 8) {
			return matchId + " " + value;
		} else {
			return splittedMatchId[7] + " " + value;
		}
	}

	/**
	 * Returns MatchId and Value of the resource using resource value as
	 * parameter
	 * 
	 * @param resources
	 * 
	 * @return
	 */

	public String getMatchIdAndValue(Resources resources) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Object[] res = (Object[]) session
				.createQuery(
						"select sm.matchId, val.resAttrValue from Resources s join s.resourceMatch sm join sm.resAttrValues val where s.pkResources = "
								+ resources.getPkResources()).uniqueResult();

		String matchId = res[0].toString() + " ";
		String value = res[1].toString();
		String[] splittedMatchId = matchId.split(":");
		tx.commit();
		session.close();
		if (splittedMatchId.length < 8) {
			return matchId + " " + value;
		} else {
			return splittedMatchId[7] + " " + value;
		}
	}

	/**
	 * Returns MatchId and Value of the action using action value as parameter
	 * 
	 * @param acts
	 * 
	 * @return
	 */

	public String getMatchIdAndValue(Actions acts) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Object[] res = (Object[]) session
				.createQuery(
						"select sm.matchId, val.actAttrValue from Actions s join s.actionMatch sm join sm.actAttrValues val where s.pkActions = "
								+ acts.getPkActions()).uniqueResult();

		String matchId = res[0].toString() + " ";
		String value = res[1].toString();
		String[] splittedMatchId = matchId.split(":");
		tx.commit();
		session.close();
		if (splittedMatchId.length < 8) {
			return matchId + " " + value;
		} else {
			return splittedMatchId[7] + " " + value;
		}
	}

	/**
	 * Returns MatchId and Value of the environment using environment value as
	 * parameter
	 * 
	 * @param envs
	 * 
	 * @return
	 */

	public String getMatchIdAndValue(Environments envs) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Object[] res = (Object[]) session
				.createQuery(
						"select sm.matchId, val.envAttrValue from Environments s join s.environmentMatch sm join sm.envAttrValues val where s.pkEnvironments = "
								+ envs.getPkEnvironments()).uniqueResult();

		String matchId = res[0].toString() + " ";
		String value = res[1].toString();
		String[] splittedMatchId = matchId.split(":");
		tx.commit();
		session.close();
		if (splittedMatchId.length < 8) {
			return matchId + " " + value;
		} else {
			return splittedMatchId[7] + " " + value;
		}
	}
	
	/**
	 * Returns @{@code List} of {@code Target}(s) which has no
	 * {@code Environment}
	 * 
	 * @return {@code List} of {@code Target}(s)
	 */
	
	@SuppressWarnings("unchecked")
	public List<Target> getTargetWithNoEnvironment() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Target> targList = (List<Target>) session
				.createQuery("select t from Target t where t.pkTarget not in (select t from Target t join t.environments env where env is not null)").list();
		System.out.println("Target size: " + targList.size());
		for(Target t : targList){
		System.out.println("Target: " + t.getEnvironments().isEmpty());
		}

		tx.commit();
		if(session.isOpen())
			session.close();
		return targList;
		

	}
	
	/**
	 * Returns @{@code List} of {@code Target}(s) which has atleast one
	 * {@code Environment}
	 * 
	 * @return {@code List} of {@code Target}(s)
	 */
	
	@SuppressWarnings("unchecked")
	public List<Target> getTargetWithEnvironment() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Target> targList = (List<Target>) session
				.createQuery("select t from Target t join t.environments env where env is not null").list();
		
		for(Target t : targList){
		System.out.println("Target: " + t.getEnvironments().isEmpty());
		}

		tx.commit();
		if(session.isOpen())
			session.close();
		return targList;
	}
}
