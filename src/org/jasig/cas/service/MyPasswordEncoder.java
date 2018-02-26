package org.jasig.cas.service;
import org.jasig.cas.authentication.handler.PasswordEncoder;
import org.jasig.cas.util.Cryption;
public class MyPasswordEncoder implements PasswordEncoder{

	@Override
	public String encode(String arg0) {
		try {
			arg0 = Cryption.enCrytor(arg0);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return arg0;
	}
}
