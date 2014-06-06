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

package com.aislab.accesscontrol.core.ui.validator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

public class DataTypeValidator implements Validator {

	/*
	 * private final static String EMAIL_PATTERN =
	 * "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$"
	 * ;
	 * 
	 * private final static Pattern EMAIL_COMPILED_PATTERN = Pattern
	 * .compile(EMAIL_PATTERN);
	 */

	private final static String INTEGER_PATTERN = "[-+]?[1-9][0-9]*|0";

	private final static Pattern INTEGER_COMPILED_PATTERN = Pattern
			.compile(INTEGER_PATTERN);

	private final static String STRING_PATTERN = "(([a-zA-Z0-9_-])+([a-zA-Z0-9'_ -])*)+";

	private final static Pattern STRING_COMPILED_PATTERN = Pattern
			.compile(STRING_PATTERN);

	private final static String ANYURI_PATTERN = "\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

	private final static Pattern ANYURI_COMPILED_PATTERN = Pattern
			.compile(ANYURI_PATTERN);

	public void validate(FacesContext context, UIComponent component,
			Object value) throws ValidatorException {

		String dataType = (String) component.getAttributes().get("item");

		if (dataType.equals("String")) {

			Matcher matcher = STRING_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("String is not valid.");
				message.setDetail("String is not valid.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equals("Integer")) {

			Matcher matcher = INTEGER_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Integer is not valid.");
				message.setDetail("Integer is not valid.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equals("Boolean")) {

			if (!value.toString().equalsIgnoreCase("true")
					&& !value.toString().equalsIgnoreCase("false")) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("Boolean Value required.");
				message.setDetail("Boolean Value required.");
				throw new ValidatorException(message);
			}
		}

		else if (dataType.equals("anyURI")) {

			Matcher matcher = ANYURI_COMPILED_PATTERN.matcher((String) value);

			if (!matcher.matches()) {

				FacesMessage message = new FacesMessage();
				message.setSeverity(FacesMessage.SEVERITY_ERROR);
				message.setSummary("URI is not valid.");
				message.setDetail("URI is not valid.");
				throw new ValidatorException(message);
			}
		}

	}
}
