package io.leitstand.security.sso.sys.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;

import java.util.Set;

import javax.enterprise.context.Dependent;

import io.leitstand.commons.rs.SystemResourceProvider;

/**
 * Provider of all Single-Sign On system resources.
 */
@Dependent
public class SsoResources implements SystemResourceProvider {

    /**
     * Returns the Single-Sign On system resources.
     * @return the Single-Sign On system resources.
     */
    @Override
    public Set<Class<?>> getResources() {
        return asSet(RefreshAccessTokenResource.class, 
                     SsoSettingsResource.class,
                     LoginConfigResource.class,
                     JWKSetMessageBodyWriter.class);
    }

}
