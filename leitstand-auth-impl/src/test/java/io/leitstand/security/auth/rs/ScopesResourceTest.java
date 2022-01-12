package io.leitstand.security.auth.rs;

import static io.leitstand.commons.model.ObjectUtil.asSet;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import io.leitstand.commons.rs.ApiResources;
import io.leitstand.security.auth.Scopes;

@RunWith(MockitoJUnitRunner.class)
public class ScopesResourceTest {

	@Scopes({"unittest.resource.a.1","unittest.resource.a.2"})
	private static final class ResourceA {
		
		@Scopes({"unittest.resource.a.public.method.1","unittest.resource.a.public.method.2"})
		public void publicMethod() {
			
		}
		
		@Scopes("unittest.resource.a.protected.method")
		protected void protectedMethod() {
			
		}

		@Scopes("unittest.resource.a.default.method")
		void defaultMethod() {
						
		}

		@SuppressWarnings("unused")
		public void methodWithoutScopes() {
			
		}
		
	}
	
	@Scopes({"unittest.resource.b"})
	private static final class ResourceB {
		
		@Scopes("unittest.resource.b.public.method")
		public void publicMethod() {
			
		}
		
	}
	
	
	@Mock
	private ApiResources resources;
	
	@InjectMocks
	private ScopesResource scopes = new ScopesResource();
	
	@Before
	public void initTestEnvironment() {
		when(resources.getClasses()).thenReturn(asSet(ResourceA.class,ResourceB.class));
		scopes.discoverScopes();
	}
	
	@Test
	public void discover_class_scopes() {
		assertTrue(scopes.getScopes().contains("unittest.resource.a.1"));
		assertTrue(scopes.getScopes().contains("unittest.resource.a.2"));
		assertTrue(scopes.getScopes().contains("unittest.resource.b"));
	}
	
	@Test
	public void discover_public_method_scopes() {
		assertTrue(scopes.getScopes().contains("unittest.resource.a.public.method.1"));
		assertTrue(scopes.getScopes().contains("unittest.resource.a.public.method.2"));
		assertTrue(scopes.getScopes().contains("unittest.resource.b.public.method"));

	}
	
	@Test
	public void discover_protected_method_scope() {
		assertTrue(scopes.getScopes().contains("unittest.resource.a.protected.method"));

	}

	@Test
	public void discover_default_method_scope() {
		assertTrue(scopes.getScopes().contains("unittest.resource.a.default.method"));

	}

	
}
