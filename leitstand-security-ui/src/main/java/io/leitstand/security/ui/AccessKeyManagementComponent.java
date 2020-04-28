package io.leitstand.security.ui;

import static io.leitstand.ui.model.Contribution.loadContribution;
import static io.leitstand.ui.model.ReasonCode.UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION;
import static java.lang.String.format;
import static java.lang.Thread.currentThread;

import java.io.IOException;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;

import io.leitstand.ui.model.Contribution;
import io.leitstand.ui.model.ModuleDescriptorException;

/**
 * Access key management UI component.
 * <p>
 * Loads access keys management UI component for the Leitstand admin console. */
@Dependent
public class AccessKeyManagementComponent {

	private static final Logger LOG = Logger.getLogger(AccessKeyManagementComponent.class.getName());
	
	@Produces
	public Contribution getWebhookAdminComponent() {
		
		try {
			return loadContribution(currentThread()
									.getContextClassLoader()
									.getResource("/META-INF/resources/ui/modules/admin/km/menu.yaml"))
				   .withBaseUri("km")
				   .build();
		} catch (IOException e) {
			LOG.warning(() -> format("%s: Cannot load access key management UI: %s", 
									 UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION.getReasonCode(), 
									 e.getMessage()));
			throw new ModuleDescriptorException(e,
												UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION,
												"km");
		}
		
	}
	
}
