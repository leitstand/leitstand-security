package io.leitstand.security.sys.model;

import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.Collections.unmodifiableSortedSet;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.empty;

import java.util.Collections;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.leitstand.commons.rs.ApiResources;
import io.leitstand.security.auth.Scopes;
import io.leitstand.security.sys.service.ResourceScopesService;

/**
 * The default <code>ResourceScopesService</code> implementation.
 * <p>
 * The resource scopes are discovered from the <code>{@literal @Scope}</code> annotations
 * on Leitstand API resources (annotated with <code>{@literal @Resource}</code>.
 */

@ApplicationScoped
public class DefaultResourceScopesService implements ResourceScopesService{

	@Inject
	private ApiResources resources;
	private SortedSet<String> scopes;

	static Set<String> declaredScopes(Class<?> resource){
		Set<String> scopes = new TreeSet<>();
		Scopes classAnnotation = resource.getAnnotation(Scopes.class);
		if(classAnnotation != null) {
			scopes.addAll(asList(classAnnotation.value()));
		}
	
		scopes.addAll(stream(resource.getDeclaredMethods())
					  .flatMap(m -> {
						  Scopes methodAnnotation = m.getAnnotation(Scopes.class);
						  if(methodAnnotation != null) {
							  return stream(methodAnnotation.value());
						  }
						  return empty();
					  })
					  .collect(toSet()));
		
		return scopes;
	}
	
	@PostConstruct
	protected void discoverScopes() {
		SortedSet<String> scopes = new TreeSet<>();
		
		for(Class<?> resource : resources.getClasses()) {
			scopes.addAll(declaredScopes(resource));
		}
		
		this.scopes = unmodifiableSortedSet(scopes);
		
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SortedSet<String> getResourceScopes() {
		return scopes;
	}
	
}
