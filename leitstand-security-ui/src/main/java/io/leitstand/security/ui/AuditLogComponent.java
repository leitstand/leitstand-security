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
 * User audit log UI component.
 * <p>
 * Loads the user audit log UI component contribution for the Leitstand administration console.
 */
@Dependent
public class AuditLogComponent {

	private static final Logger LOG = Logger.getLogger(AuditLogComponent.class.getName());
	
	@Produces
	public Contribution getWebhookAdminComponent() {
		
		try {
			return loadContribution(currentThread()
									.getContextClassLoader()
									.getResource("/META-INF/resources/ui/modules/admin/log/menu.yaml"))
				   .withBaseUri("um")
				   .build();
		} catch (IOException e) {
			LOG.warning(() -> format("%s: Cannot load audit log UI: %s", 
									 UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION.getReasonCode(), 
									 e.getMessage()));
			throw new ModuleDescriptorException(e,
												UIM0002E_CANNOT_PROCESS_MODULE_EXTENSION,
												"log");
		}
		
	}
	
}
