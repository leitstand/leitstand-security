package io.leitstand.security.ui;

import static io.leitstand.ui.model.Contribution.loadContribution;
import static io.leitstand.ui.model.ReasonCode.UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION;
import static java.lang.String.format;
import static java.lang.Thread.currentThread;

import java.io.IOException;
import java.util.logging.Logger;

import javax.enterprise.inject.Produces;

import io.leitstand.ui.model.Contribution;
import io.leitstand.ui.model.ModuleDescriptorException;

/**
 * User management UI component.
 * <p>
 * Loads the user management UI component contribution for the Leitstand administration console.
 */
public class UserAdministrationComponent2 {

	private static final Logger LOG = Logger.getLogger(UserAdministrationComponent2.class.getName());
	
	@Produces
	public Contribution getWebhookAdminComponent() {
		
		try {
			return loadContribution(currentThread()
									.getContextClassLoader()
									.getResource("/META-INF/resources/ui/modules/admin/um/menu.yaml"))
				   .withBaseUri("um")
				   .build();
		} catch (IOException e) {
			LOG.warning(() -> format("%s: Cannot load user management UI: %s", 
									 UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION.getReasonCode(), 
									 e.getMessage()));
			throw new ModuleDescriptorException(e,
												UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION,
												"um");
		}
		
	}
	
}
