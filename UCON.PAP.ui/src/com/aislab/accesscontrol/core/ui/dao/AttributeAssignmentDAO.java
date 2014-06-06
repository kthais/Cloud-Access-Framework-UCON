package com.aislab.accesscontrol.core.ui.dao;

import java.util.List;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.AttributeAssignment;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

public class AttributeAssignmentDAO {

	 public static SessionFactory sessionFactory;
	 public static Session session;
	 public static Transaction tx;
	 
	 public AttributeAssignment aa;
	 
	 public AttributeAssignment createAttributeAssignment(String attId,String attVal,String attDescription){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 aa =  new AttributeAssignment(attId,attVal,attDescription);
		 aa.setDataType("http://www.w3.org/2001/XMLSchema#string");
		 System.out.println(aa.getDataType());
	     session.persist(aa);
	     tx.commit();
	     session.close();
	     return aa;

		 

	 }
	 public List<AttributeAssignment> getAllAttributeAssignments(){
		 sessionFactory = HibernateUtil.configureSessionFactory();
		 session = sessionFactory.openSession();
		 tx = session.beginTransaction();
		 List<AttributeAssignment> aas = session.createQuery("from AttributeAssignment aa").list();
	     tx.commit();
	     session.close();
	     return aas;
	 }

	
}
