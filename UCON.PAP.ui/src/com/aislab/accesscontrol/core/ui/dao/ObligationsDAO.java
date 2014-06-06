package com.aislab.accesscontrol.core.ui.dao;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.junit.BeforeClass;
import org.junit.Test;

import com.aislab.accesscontrol.core.entities.AttributeAssignment;
import com.aislab.accesscontrol.core.entities.Obligations;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

public class ObligationsDAO {
	 public static SessionFactory sessionFactory;
	 public static Session session;
	 public static Transaction tx;
	 
	 public Policy policy;
	 public Obligations obl;
	 
	 public Obligations createObligations(String obligationId, String description, String fulfillOn, 
			 Set<AttributeAssignment> attrAssignments){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 obl = new Obligations(obligationId, description, fulfillOn, attrAssignments);
	     session.persist(obl);
	     tx.commit();
	     session.close();
	     return obl;
		 }
	 

	 
	 public void updateObligations(Long pkObligation, String obligationId, String description, String fulfillOn, 
			 Set<AttributeAssignment> attrAssignments){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 Query query = session.createQuery("update Obligations set obligationId = :obligationId, " +
		 		"description = :description, fulfillOn = :fulfillOn where pkObligation = :pkObligation");
			query.setParameter("obligationId", obligationId);
			query.setParameter("description", description);
			query.setParameter("fulfillOn", fulfillOn);
			query.setParameter("pkObligation", pkObligation);
			query.executeUpdate();	

	     tx.commit();
	     session.close(); 
		 }
	 
	 public List<Obligations> populateObligations(){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 @SuppressWarnings("unchecked")
		 List<Obligations> oblList = session.createQuery(" from Obligations ").list();	 
		 
	     tx.commit();
	     session.close();
		 return oblList;
	 }
	 
	 //List<AttributeAssignment>
	 public List<AttributeAssignment> getAttrAssignments(Long pkObligation){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 Query q = session.createQuery("select o.attributeAssignments from Obligations o where o.pkObligation = " + pkObligation);	 
		 List<AttributeAssignment> attrAssignment = q.list();
	     tx.commit();
	     session.close();
		 return attrAssignment;
		 
	 }
	 
	 public void deleteObligations(Long pkObligation){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 Obligations temp = (Obligations) session.load(Obligations.class, pkObligation);
		 session.delete(temp);
	     tx.commit();
	     session.close(); 
	 }	 
	
	 

}
