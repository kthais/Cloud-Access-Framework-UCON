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

package com.aislab.accesscontrol.jboss.ucon.pep;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * This class will get Connection URL, User-name and Password from Configuration
 * File And also get Obligation From the Response
 * 
 * @author Muhammad Sadiq Alvi and Junaid Sarfraz
 * 
 */
public class XMLParser {

	/**
	 * It Parses Config file for Connection Parses XML file and returns a
	 * DBHandler Object
	 * 
	 * @param filename
	 *            Filename of Config file
	 * @return DatabaseHandler (initialized Object)
	 */

	/**
	 * Its extract the obligations from response file
	 * 
	 * @param responseFile
	 *            Path of response.xml
	 * @return Array list of all Obligations that get from response files
	 */
	@SuppressWarnings("finally")
	public static ArrayList<MyObligation> getObligationIdFromResponse(
			String responseFile) {
		String OblId = null;
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory
				.newInstance();
		DocumentBuilder docBuilder;
		ArrayList<MyObligation> obls = new ArrayList<MyObligation>();
		try {
			docBuilder = docBuilderFactory.newDocumentBuilder();

			Document doc = docBuilder.parse(new File(responseFile));
			NodeList rootNode = doc.getElementsByTagName("Obligations");
			for (int h = 0; h < rootNode.getLength(); h++) {
				Node Obs = rootNode.item(h);
				NodeList oNodes = Obs.getChildNodes();
				for (int j = 0; j < oNodes.getLength(); j++) {
					if (oNodes.item(j).getNodeName().equals("Obligation")) {
						NamedNodeMap attMap = oNodes.item(j).getAttributes();
						OblId = attMap.getNamedItem("ObligationId")
								.getNodeValue();
						NodeList attAssignments = oNodes.item(j)
								.getChildNodes();
						MyObligation ob = new MyObligation();
						ob.setObId(OblId);
						ArrayList<String[]> Atts = new ArrayList<String[]>();

						for (int p = 0; p < attAssignments.getLength(); p++) {
							String[] attr = new String[3];
							if (attAssignments.item(p).getNodeName()
									.equals("AttributeAssignment")) {
								NamedNodeMap attM = attAssignments.item(p)
										.getAttributes();
								attr[0] = attM.getNamedItem("AttributeId")
										.getNodeValue();
								attr[1] = attM.getNamedItem("DataType")
										.getNodeValue();
								attr[2] = attAssignments.item(p)
										.getTextContent();
								Atts.add(attr);
							}
						}
						ob.setAttAssignment(Atts);
						obls.add(ob);

					}
				}
			}
			return obls;
		} catch (Exception e) {

		} finally {
			return obls;
		}
	}
}
