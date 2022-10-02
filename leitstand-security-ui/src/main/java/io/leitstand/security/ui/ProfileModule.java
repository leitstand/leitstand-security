package io.leitstand.security.ui;

import static io.leitstand.ui.model.ModuleDescriptor.readModuleDescriptor;
import static io.leitstand.ui.model.ReasonCode.UIM0001E_CANNOT_PROCESS_MODULE_DESCRIPTOR;
import static java.lang.String.format;
import static java.lang.Thread.currentThread;
import static java.util.logging.Level.FINE;
import static java.util.logging.Logger.getLogger;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;

import io.leitstand.ui.model.ModuleDescriptor;
import io.leitstand.ui.model.ModuleDescriptorException;

@Dependent
public class ProfileModule {

	private static final Logger LOG = getLogger(ProfileModule.class.getName());
	private static final String MODULE_NAME = "profile";
	
	@Produces
	public ModuleDescriptor getAdminModule() {
		
		try {
			URL moduleDescriptor =  currentThread()
									.getContextClassLoader()
									.getResource(format("/META-INF/resources/ui/modules/%s/module.yaml",
														MODULE_NAME));
		
				return readModuleDescriptor(moduleDescriptor)
					   .build();
		} catch (IOException e) {
			LOG.severe(format("%s: Cannot load %s module descriptor. Reason: %s",
							  UIM0001E_CANNOT_PROCESS_MODULE_DESCRIPTOR.getReasonCode(),
							  MODULE_NAME,
							  e.getMessage()));
			LOG.log(FINE,e.getMessage(),e);
			throw new ModuleDescriptorException(e,
												UIM0001E_CANNOT_PROCESS_MODULE_DESCRIPTOR,
												MODULE_NAME);
		}
		
	}
	
	
}
