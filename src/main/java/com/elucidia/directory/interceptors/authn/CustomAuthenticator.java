package com.elucidia.directory.interceptors.authn;

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.directory.server.core.authn.Authenticator;

public class CustomAuthenticator extends AbstractAuthenticator implements Authenticator {
	public CustomAuthenticator() {
		super(AuthenticationLevel.SIMPLE);
	}

	public CustomAuthenticator(Dn baseDn) {
		super(AuthenticationLevel.SIMPLE, baseDn);
	}

	public CustomAuthenticator(int cacheSize) {
		super(AuthenticationLevel.SIMPLE, Dn.ROOT_DSE);
	}

	public CustomAuthenticator(int cacheSize, Dn baseDn) {
		super(AuthenticationLevel.SIMPLE, baseDn);
	}

	@Override
	public LdapPrincipal authenticate(BindOperationContext bindContext) throws LdapException {
		return getPrincipal(bindContext);
	}
	
	private LdapPrincipal getPrincipal(BindOperationContext bindContext) {
		byte[] password = bindContext.getCredentials();

		LdapPrincipal principal = new LdapPrincipal(
				getDirectoryService().getSchemaManager(), 
				bindContext.getDn(),
				AuthenticationLevel.NONE);

		principal.setUserPassword(password);

		return principal;
	}
}
