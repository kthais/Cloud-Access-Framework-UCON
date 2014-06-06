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
import org.junit.Test;

import com.aislab.accesscontrol.core.entities.Obligations;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.PolicySet;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.entities.VarDef;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

public class PolicyDAO {
	public static SessionFactory sessionFactory;
	public static Session session;
	public static Transaction tx;
	Query query;

	/**
	 * Selecting all the Policies from the database
	 * 
	 * @return List of all the policies
	 */
	@SuppressWarnings("unchecked")
	public List<Policy> selectPolicy() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Policy");
		List<Policy> pol = query.list();

		tx.commit();
		session.close();
		return pol;
	}

	/**
	 * Selecting a specific Policy from the database
	 * 
	 * @param pkPolicy
	 *            primary key of the Policy
	 * @return required policy
	 */
	public Policy selectPolicy(Long pkPolicy) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Policy p where p.pkPolicy = "
				+ pkPolicy);
		Policy pol = (Policy) query.uniqueResult();

		tx.commit();
		session.close();
		return pol;
	}

	/**
	 * Creating Policy with provided arguments
	 * 
	 * @param policyId
	 *            , Id of the Policy
	 * @param ruleCombAlgo
	 *            , Rule Combining Algorithm of the Policy
	 * @param targ
	 *            , Target of the Policy
	 * @param description
	 *            , Description of the Policy
	 * @param rules
	 *            , Applied Rules of the Policy
	 */
	public void createPolicy(String policyId, String ruleCombAlgo, Target targ,
			String description, Set<Rule> rules) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		// Creating a new object of Policy with Provided Arguments
		Policy pol = new Policy(targ, policyId, ruleCombAlgo, description,
				rules);

		session.persist(pol);
		tx.commit();
		session.close();
	}

	public void createPolicy(String policyId, String ruleCombAlgo, Target targ,
			String description, Set<Rule> rules, Set<Obligations> obligations) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		// Creating a new object of Policy with Provided Arguments
		Policy pol = new Policy(targ, policyId, ruleCombAlgo, description,
				new HashSet(new ArrayList<PolicySet>()), new HashSet(
						new ArrayList<VarDef>()), rules, obligations);

		session.persist(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Updating an already created Policy
	 * 
	 * @param pkPolicy
	 *            Primary Key of the policy that is to be modified
	 * @param rules
	 *            applied rules on the Policy
	 */
	public void updatePolicy(Long pkPolicy, Set<Rule> rules) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Policy pol = (Policy) session.load(Policy.class, pkPolicy);
		// Policy pol = (Policy) query.uniqueResult();
		pol.setRules(rules);

		session.saveOrUpdate(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Updating already created Policy
	 * 
	 * @param pkPolicy
	 *            , primary key of the Policy
	 * @param name
	 *            , name of the Policy
	 * @param description
	 *            , description of the Policy
	 * @param ruleCombAlgo
	 *            , rule combining algorithm of the Policy
	 * @param targ
	 *            , target of the Policy
	 * @param rules
	 *            , Rules applicable on the Policy
	 */
	public void updatePolicy(Long pkPolicy, String name, String description,
			String ruleCombAlgo, Target targ, Set<Rule> rules) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Policy p where p.pkPolicy ="
				+ pkPolicy);
		Policy pol = (Policy) query.uniqueResult();
		// Setting the attributes of the Policy
		pol.setPolicyId(name);
		pol.setDescription(description);
		pol.setRuleCombAlgo(ruleCombAlgo);
		pol.setTarget(targ);
		pol.setRules(rules);

		session.persist(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Updating already created Policy
	 * 
	 * @param pkPolicy
	 *            , primary key of the Policy
	 * @param name
	 *            , name of the Policy
	 * @param description
	 *            , description of the Policy
	 * 
	 */
	public void updatePolicy(Long pkPolicy, String name, String description) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Policy p where p.pkPolicy ="
				+ pkPolicy);
		Policy pol = (Policy) query.uniqueResult();
		// Setting the attributes of the Policy
		pol.setPolicyId(name);
		pol.setDescription(description);

		session.persist(pol);
		tx.commit();
		session.close();
	}

	/*
	 * public void updatePolicy(Long pkPolicy, Set<Rule> rules) { sessionFactory
	 * = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction();
	 * 
	 * query = session.createQuery("from Policy p where p.pkPolicy =" +
	 * pkPolicy); Policy pol = (Policy) query.uniqueResult();
	 * 
	 * pol.setRules(rules); System.out.println(
	 * "saveUpdatePolicyRule----- updatePolicy----inside query------");
	 * 
	 * session.persist(pol); tx.commit(); session.close();
	 * 
	 * System.out.println("saveUpdatePolicyRule----- updatePolicy----------");
	 * 
	 * }
	 */

	/*
	 * public void updatePolicy(Long pkPolicy, Set<Rule> rules) { sessionFactory
	 * = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction();
	 * 
	 * query = session.createQuery("from Policy p where p.pkPolicy =" +
	 * pkPolicy); Policy pol = (Policy) query.uniqueResult();
	 * //pol.setRules(null); pol.setRules(rules); //pol.setRules(rules);
	 * System.out
	 * .println("saveUpdatePolicyRule----- updatePolicy----inside query------");
	 * 
	 * session.persist(pol); tx.commit(); session.close();
	 * 
	 * System.out.println("saveUpdatePolicyRule----- updatePolicy----------");
	 * 
	 * }
	 */
	/**
	 * Updating Policy Rules
	 * 
	 * @param pkPolicy
	 *            Primary key of the Policy
	 * @param rules
	 *            List containing rules applied on the Policy
	 */
	public void updatePolicyRule(Long pkPolicy, Set<Rule> rules) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Policy pol = (Policy) session.load(Policy.class, pkPolicy);
		// Setting Rules in the POlicy
		pol.setRules(rules);
		session.persist(pol);
		tx.commit();
		session.close();
	}

	/**
	 * UPdating already created Policy
	 * 
	 * @param pkPolicy
	 *            Primary key of the Policy
	 * @param rules
	 *            List of rules applied on the Policy
	 */
	public void updatePolicy(Long pkPolicy, List<Rule> rules) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Policy p where p.pkPolicy ="
				+ pkPolicy);
		// Getting Policy
		Policy pol = (Policy) query.uniqueResult();
		// pol.setRules(null);
		pol.setRules(new HashSet<Rule>(rules));
		// pol.setRules((Set<Rule>) rules);
		// System.out
		// .println("saveUpdatePolicyRule----- updatePolicy----inside query------");

		session.persist(pol);
		tx.commit();
		session.close();

		// System.out.println("saveUpdatePolicyRule----- updatePolicy----------");

	}

	/*
	 * public void deletePolicyRules(Policy pol, Rule deleteRule){
	 * sessionFactory = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction(); //
	 * List<Rule> polRules =
	 * session.createQuery("select p.rules from Policy p where p.pkPolicy = " +
	 * pol.getPkPolicy()).list(); List<Rule> polRules = (List<Rule>)
	 * session.createQuery("select p.rules from Policy p where p.pkPolicy = " +
	 * pol.getPkPolicy()).list(); for(Rule rul: polRules){ if(rul.getPkRule() ==
	 * deleteRule.getPkRule()) polRules.remove(rul); }
	 * 
	 * Set<Rule> updatedRuleSet = new HashSet<Rule>(polRules);
	 * pol.setRules(updatedRuleSet); session.persist(pol);
	 * System.out.println("yumna is great ----------------"); tx.commit();
	 * session.close(); }
	 */
	/*
	 * public void deletePolicyRules(Policy pol, Rule deleteRule){ // tx =
	 * session.beginTransaction(); sessionFactory =
	 * HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction();
	 * 
	 * //if(!session.contains(pol)) // session.load(Policy.class,
	 * pol.getPkPolicy()); List<Rule> polRules = (List<Rule>)
	 * session.createQuery("select p.rules from Policy p where p.pkPolicy = " +
	 * pol.getPkPolicy()).list();
	 * 
	 * Set<Rule> updatedRuleSet = pol.getRules();
	 * 
	 * for(Rule rul: updatedRuleSet){ if(rul.getPkRule() ==
	 * deleteRule.getPkRule()) updatedRuleSet.remove(rul); }
	 * 
	 * 
	 * pol.setRules(updatedRuleSet); session.persist(pol); tx.commit();
	 * 
	 * }
	 */
	/*
	 * public void deletePolicyRules(Policy pol, Rule deleteRule){
	 * sessionFactory = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction();
	 * if(!session.contains(pol.getRules())) session.update(pol.getRules());
	 * Set<Rule> updatedRuleSet = pol.getRules();
	 * 
	 * for(Rule rul: updatedRuleSet){ if(rul.getPkRule() ==
	 * deleteRule.getPkRule()) updatedRuleSet.remove(rul); }
	 * 
	 * 
	 * pol.setRules(updatedRuleSet); session.persist(pol); tx.commit();
	 * 
	 * }
	 */

	/**
	 * Deleting Rules from a Policy
	 * 
	 * @param pol
	 *            Policy
	 * @param deleteRule
	 *            Already present Rules that are to be removed
	 */
	@SuppressWarnings("unchecked")
	public void deletePolicyRules(Policy pol, Rule deleteRule) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		if (!session.contains(pol))
			session.load(Policy.class, pol.getPkPolicy());
		List<Rule> updatedRuleSet = (List<Rule>) session.createQuery(
				"select p.rules from Policy p where p.pkPolicy = "
						+ pol.getPkPolicy()).list();

		Iterator<Rule> iter = updatedRuleSet.iterator();
		while (iter.hasNext()) {
			if (iter.next().getPkRule() == deleteRule.getPkRule())
				iter.remove();
		}

		pol.setRules(new HashSet<Rule>(updatedRuleSet));
		session.saveOrUpdate(pol);
		tx.commit();
		session.close();
	}

	/*
	 * public void deletePolicyRules(Policy pol, Rule deleteRule){
	 * sessionFactory = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction();
	 * if(!session.contains(pol)) session.load(Policy.class, pol.getPkPolicy());
	 * List<Rule> updatedRuleSet =
	 * session.createQuery("select p.rules from Policy p where p.pkPolicy = " +
	 * pol.getPkPolicy()).list(); // Set<Rule> updatedRuleSet = pol.getRules();
	 * 
	 * for(Rule rul: updatedRuleSet){ if(rul.getPkRule() ==
	 * deleteRule.getPkRule()) updatedRuleSet.remove(rul); }
	 * 
	 * 
	 * pol.setRules(new HashSet<Rule>(updatedRuleSet));
	 * session.saveOrUpdate(pol); tx.commit();
	 * 
	 * }
	 */

	/*
	 * public void deletePolicyRules(Policy pol, Rule deleteRule){
	 * 
	 * sessionFactory = HibernateUtil.configureSessionFactory(); session =
	 * sessionFactory.openSession(); tx = session.beginTransaction(); List<Rule>
	 * updatedRuleSet = (List<Rule>)
	 * session.createQuery("select p.rules from Policy p where p.pkPolicy = " +
	 * pol.getPkPolicy()).list();
	 * 
	 * 
	 * for(Rule rul: updatedRuleSet){ if(rul.getPkRule() ==
	 * deleteRule.getPkRule()) updatedRuleSet.remove(rul); }
	 * 
	 * 
	 * pol.setRules(new HashSet(updatedRuleSet)); session.persist(pol);
	 * tx.commit();
	 *//*
		 * //tx = session.beginTransaction(); sessionFactory =
		 * HibernateUtil.configureSessionFactory(); session =
		 * sessionFactory.openSession(); tx = session.beginTransaction();
		 * 
		 * 
		 * // List<Rule> polRules =
		 * session.createQuery("select p.rules from Policy p where p.pkPolicy = "
		 * + pol.getPkPolicy()).list(); List<Rule> polRules = (List<Rule>)
		 * session
		 * .createQuery("select p.rules from Policy p where p.pkPolicy = " +
		 * pol.getPkPolicy()).list();
		 * 
		 * 
		 * for(Rule rul: polRules){ if(rul.getPkRule() ==
		 * deleteRule.getPkRule()) polRules.remove(rul); }
		 * 
		 * Set<Rule> updatedRuleSet = new HashSet<Rule>(polRules);
		 * pol.setRules(updatedRuleSet); session.persist(pol); tx.commit();
		 */// }

	/**
	 * Deleting creted Policy
	 * 
	 * @param pkPolicy
	 *            primary key of the Policy
	 */
	@Test
	public void deletePolicy(Long pkPolicy) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Policy p where p.pkPolicy = "
				+ pkPolicy);
		Policy pol = (Policy) query.uniqueResult();

		session.delete(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Selecting applied rules on a policy
	 * 
	 * @param polPk
	 *            primary key of the policy
	 * @return list containing Rules that are applied on specified Policy
	 */
	@SuppressWarnings("unchecked")
	public ArrayList<Rule> selectRules(Long polPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select pol.rules from Policy pol where pol.pkPolicy ="
						+ polPk);
		ArrayList<Rule> appliedRules = (ArrayList<Rule>) query.list();

		tx.commit();
		session.close();
		return appliedRules;

	}

	/**
	 * Selecting applied obligation on a policy
	 * 
	 * @param polPk
	 *            primary key of the Policy
	 * @return List containing all the obligations applied on the Policy
	 */
	@SuppressWarnings("unchecked")
	public List<Obligations> selectObligations(Long polPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select pol.obligations from Policy pol where pol.pkPolicy ="
						+ polPk);
		List<Obligations> appliedObligations = query.list();

		tx.commit();
		session.close();
		return appliedObligations;

	}

	/**
	 * Getting target of the policy
	 * 
	 * @param pkPolicy
	 *            primary key of the policy
	 * @return target of the specified policy
	 */
	public Target getTarget(Long pkPolicy) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Target targ = (Target) session.createQuery(
				"select p.target from Policy p where p.pkPolicy = " + pkPolicy)
				.uniqueResult();
		tx.commit();
		session.close();
		return targ;
	}

	/**
	 * Getting rule of the policy
	 * 
	 * @param pkPolicy
	 *            primary key of the policy
	 * @return rule of the specified policy
	 */
	public Rule getRule(Long pkPolicy) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session
				.createQuery("select pol.rules from Policy pol where pol.pkPolicy ="
						+ pkPolicy);
		List<Rule> appliedRules = query.list();
		Iterator<Rule> it = appliedRules.iterator();
		Rule myRule = null;
		if (it.hasNext())
			myRule = it.next();
		tx.commit();
		session.close();
		return myRule;
	}

	/**
	 * Selecting Target
	 * 
	 * @param targetPk
	 *            orimary key of the target
	 * @return specified target
	 */
	public Target selectTarget(Long targetPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Target tar where tar.pkTarget = "
				+ targetPk);
		Target tar = (Target) query.uniqueResult();
		// System.out.println(tar.getDescription());

		tx.commit();
		session.close();
		return tar;

	}

	/**
	 * Deleting Policy
	 * 
	 * @param pkPolicy
	 *            primary key of the Policy
	 */
	public void deleteTarget(Long pkPolicy) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Policy where pkPolicy =" + pkPolicy);
		Policy policy = (Policy) query.uniqueResult();
		policy.setTarget(null);
		// policy.getRules();
		session.update(policy);
		tx.commit();
		session.close();

	}

	/**
	 * Getting Rules that are not present in the Policy
	 * 
	 * @param pol
	 *            primary key of the policy
	 * @return List containing all the rules that are not present in the policy
	 */
	@SuppressWarnings("unchecked")
	public List<Rule> selectRulesToAdd(Policy pol) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		List<Rule> rulList = (List<Rule>) session
				.createQuery(
						"from Rule r where r.pkRule not in (select rul.pkRule from Policy p join p.rules rul where p.pkPolicy = "
								+ pol.getPkPolicy() + ")").list();

		tx.commit();
		session.close();
		return rulList;

	}

	/**
	 * Adding rules in the policy
	 * 
	 * @param pol
	 *            Specified Policy
	 * @param rul
	 *            List of rules that needs to be included in the policy
	 */
	@SuppressWarnings("unchecked")
	public void addPolicyRule(Policy pol, List<Rule> rul) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		List<Rule> rulList = (List<Rule>) session.createQuery(
				"select p.rules from Policy p where p.pkPolicy = "
						+ pol.getPkPolicy()).list();

		rulList.addAll(rul);
		pol.setRules(new HashSet<Rule>(rulList));

		session.saveOrUpdate(pol);

		tx.commit();
		session.close();
	}
}
