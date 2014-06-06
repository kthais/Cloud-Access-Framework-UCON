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

import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Rules
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @author Salman Ahmed Ansari <10besesansari@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class RuleDAO {

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

	/**
	 * A string variable to store queries
	 */
	String qstring;

	/**
	 * Selecting All the Rules from the Rule
	 * 
	 * @return List of all the available Rules
	 */
	@SuppressWarnings("unchecked")
	public List<Rule> selectRule() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Rule");
		List<Rule> rules = query.list();

		tx.commit();
		session.close();
		return rules;
	}

	/**
	 * Getting Rule id and Description of all available Rules
	 * 
	 * @return List containing Rule id and Description of all available Rules
	 */
	@SuppressWarnings("unchecked")
	public List<Object[]> populateRuleList() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("Select r.ruleId, r.description, "
				+ " from Rule r");
		List<Object[]> rules = query.list();

		tx.commit();
		session.close();
		return rules;
	}

	/**
	 * Selecting target
	 * 
	 * @param targetPk
	 *            primaey key of the Target
	 * @return Specified Target
	 */
	public Target selectTarget(Long targetPk) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Target tar where tar.pkTarget = "
				+ targetPk);
		Target tar = (Target) query.uniqueResult();

		tx.commit();
		session.close();
		return tar;

	}

	/**
	 * Selecting Condition
	 * 
	 * @param condPk
	 *            primary key of the Condition
	 * @return specified Condition
	 */
	public Condition selectCondition(Long condPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from Condition con where con.pkCondition = "
						+ condPk);
		Condition cond = (Condition) query.uniqueResult();

		tx.commit();
		session.close();
		return cond;

	}

	/**
	 * Creating New Rule
	 * 
	 * @param ruleId
	 *            Rule id of the newly created Rule
	 * @param effect
	 *            effect of the new rule
	 * @param target
	 *            target of the new rule
	 * @param description
	 *            description of the new rule
	 */
	public Rule createRule(String ruleId, String effect, Target target,
			String description) {
		Target testTarget = null;
		Rule testRule;

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		testRule = new Rule(ruleId, effect);
		testRule.setDescription(description);
		if (target != null && target.getPkTarget() != null) {
			qstring = "from Target t where t.pkTarget = "
					+ target.getPkTarget();

			query = session.createQuery(qstring);

			testTarget = (Target) query.uniqueResult();
			session.update(testTarget);
			testRule.setTarget(target);
		}

		session.persist(testRule);

		tx.commit();
		session.close();
		return testRule;
	}

	/**
	 * Creating new rule
	 * 
	 * @param condition
	 *            condition of the new Rule
	 * @param ruleId
	 *            RuleId of the new Rule
	 * @param effect
	 *            effect of the new Rule
	 */
	public Rule createRule(Condition condition, String ruleId, String effect) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Rule rule = new Rule(condition, ruleId, effect);
		session.persist(rule);
		tx.commit();
		session.close();
		return rule;
	}

	/**
	 * Creating New Rule
	 * 
	 * @param target
	 *            of the new rule
	 * @param condition
	 *            of the new rule
	 * @param ruleId
	 *            of the new rule
	 * @param description
	 *            of the new rule
	 * @param effect
	 *            of the new rule
	 * @param policies
	 *            policies in which this rule is present
	 */
	public Rule createRule(Target target, Condition condition, String ruleId,
			String description, String effect, Set<Policy> policies) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Rule rule = new Rule(target, condition, ruleId, description, effect,
				policies);
		session.persist(rule);
		tx.commit();
		session.close();
		return rule;
	}

	/**
	 * Updating already created Rule
	 * 
	 * @param pkRule
	 *            primary key of the rule
	 * @param description
	 *            of the new Rule
	 * @param ruleId
	 *            Id of the new Rule
	 * @param effect
	 *            of the new Rule
	 * @param target
	 *            of the new Rule
	 */
	public void updateRule(Long pkRule, String description, String ruleId,
			String effect, Target target) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Rule r where r.pkRule =" + pkRule);
		Rule rule = (Rule) query.uniqueResult();
		// Setting attributes of the Rule
		rule.setDescription(description);
		rule.setRuleId(ruleId);
		rule.setEffect(effect);
		rule.setTarget(target);

		session.persist(rule);
		tx.commit();
		session.close();
	}

	/**
	 * Update already created Rule
	 * 
	 * @param pkRule
	 *            primary key of the Rule
	 * @param description
	 *            of the rule
	 * @param ruleId
	 *            id of the rule
	 * @param effect
	 *            of the rule
	 */
	public void updateRule(Long pkRule, String description, String ruleId,
			String effect) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Rule r where r.pkRule =" + pkRule);
		Rule rule = (Rule) query.uniqueResult();
		// Setting Attribute of the Rule
		rule.setDescription(description);
		rule.setRuleId(ruleId);
		rule.setEffect(effect);
		session.persist(rule);
		tx.commit();
		session.close();
	}

	/**
	 * Updating Rule
	 * 
	 * @param pkRule
	 *            primary key of the rule
	 * @param description
	 *            of the rule
	 * @param ruleId
	 *            id of the rule
	 * @param effect
	 *            of the rule
	 * @param target
	 *            of the rule
	 * @param condition
	 *            of the rule
	 */
	public void updateRule(Long pkRule, String description, String ruleId,
			String effect, Target target, Condition condition) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Rule r where r.pkRule =" + pkRule);
		Rule rule = (Rule) query.uniqueResult();
		// Setting attributes of the Rule
		rule.setDescription(description);
		rule.setRuleId(ruleId);
		rule.setEffect(effect);
		rule.setTarget(target);
		rule.setCondition(condition);
		session.persist(rule);
		tx.commit();
		session.close();
	}

	/**
	 * Updating already created Rule
	 * 
	 * @param pkRule
	 *            primary key of the Rule
	 * @param target
	 *            of the Rule
	 */
	public void updateRule(Long pkRule, Target target) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Rule r where r.pkRule =" + pkRule);
		Rule rule = (Rule) query.uniqueResult();
		rule.setTarget(target);
		session.persist(rule);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting Rule
	 * 
	 * @param pkRule
	 *            primary key of the Rule
	 */

	public void deleteRule(Long pkRule) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Rule r where r.pkRule = " + pkRule);
		Rule rule = (Rule) query.uniqueResult();

		session.delete(rule);
		tx.commit();
		session.close();
	}

	/**
	 * Getting target of the Rule
	 * 
	 * @param pkRule
	 *            primary key of the Rule
	 * @return target
	 */
	public Target getTarget(Long pkRule) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Target targ = (Target) session.createQuery(
				"select r.target from Rule r where r.pkRule = " + pkRule)
				.uniqueResult();
		tx.commit();

		return targ;
	}

	/**
	 * Getting Condition of the Rule
	 * 
	 * @param pkRule
	 *            primary key of the Rule
	 * @return condition
	 */
	public Condition getCondition(Long pkRule) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Condition cond = (Condition) session.createQuery(
				"select r.condition from Rule r where r.pkRule = " + pkRule)
				.uniqueResult();
		tx.commit();

		return cond;
	}
}
