package io.leitstand.security.auth.rs;

import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.empty;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.leitstand.commons.rs.ApiResources;
import io.leitstand.security.auth.Scopes;

@ApplicationScoped
@Path("/_/scopes")
@Produces(APPLICATION_JSON)
public class ScopesResource {

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
		this.scopes = new TreeSet<>();
		
		for(Class<?> resource : resources.getClasses()) {
			scopes.addAll(declaredScopes(resource));
		}
		
	}
	
	@GET
	public SortedSet<String> getScopes(){
		return scopes;
	}
	
	
}
