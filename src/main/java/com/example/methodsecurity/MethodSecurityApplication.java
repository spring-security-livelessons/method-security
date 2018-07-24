package com.example.methodsecurity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.security.RolesAllowed;
import javax.persistence.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableGlobalMethodSecurity(
	jsr250Enabled = true,
	securedEnabled = true,
	prePostEnabled = true
)
public class MethodSecurityApplication {

		// this is from spring-security-data
		@Bean
		SecurityEvaluationContextExtension securityEvaluationContextExtension() {
				return new SecurityEvaluationContextExtension();
		}

		public static void main(String[] args) {
				SpringApplication.run(MethodSecurityApplication.class, args);
		}
}

@Slf4j
@Component
class Runner implements ApplicationRunner {

		private final UserRepository userRepository;
		private final AuthorityRepository authorityRepository;
		private final MessageRepository messageRepository;
		private final UserRepositoryUserDetailsService userDetailsService;

		Runner(UserRepository userRepository,
									AuthorityRepository authorityRepository,
									MessageRepository messageRepository,
									UserRepositoryUserDetailsService userDetailsService) {
				this.userRepository = userRepository;
				this.authorityRepository = authorityRepository;
				this.messageRepository = messageRepository;
				this.userDetailsService = userDetailsService;
		}

		private void authenticate(String username) {
				UserDetails principal = this.userDetailsService.loadUserByUsername(username);
				Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);
				log.info("authenticated " + username + ".");
		}

		private void access(String username, Long id, Function<Long, Message> msgFunction) {
				try {
						this.authenticate(username);
						log.info("result for " + username + ": " + msgFunction.apply(id));
				}
				catch (Exception x) {
						log.error("oops! can't access that message as " + username + "!");
				}
		}

		@Override
		@Transactional
		public void run(ApplicationArguments args) throws Exception {

				// lets install some data!
				Authority admin = this.authorityRepository.save(new Authority("ADMIN")),
					user = this.authorityRepository.save(new Authority("USER"));

				User josh = this.userRepository.save(new User("jlong", "password", user)),
					rob = this.userRepository.save(new User("rwinch", "password", user, admin));

				Message forRob = this.messageRepository.save(new Message("this is a message for Rob", rob));

				log.info("josh: " + this.userDetailsService.loadUserByUsername(josh.getEmail()));
				log.info("rob: " + this.userDetailsService.loadUserByUsername(rob.getEmail()));

				access(josh.getEmail(), forRob.getId(), messageRepository::findByIdPreAuthorize);
				access(rob.getEmail(), forRob.getId(), messageRepository::findByIdPreAuthorize);

				access(josh.getEmail(), forRob.getId(), messageRepository::findByIdRolesAllowed);
  		access(rob.getEmail(), forRob.getId(), messageRepository::findByIdRolesAllowed);

				access(josh.getEmail(), forRob.getId(), messageRepository::findByIdSecured);
				access(rob.getEmail(), forRob.getId(), messageRepository::findByIdSecured);

				access(josh.getEmail(), forRob.getId(), messageRepository::findByIdBeanCheck);
				access(rob.getEmail(), forRob.getId(), messageRepository::findByIdBeanCheck);

				authenticate(rob.getEmail());
				this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(msg -> log.info("found " + msg));

				authenticate(josh.getEmail());
				this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(msg -> log.info("found " + msg));

		}


}

interface UserRepository extends JpaRepository<User, Long> {
		User findByEmail(String email);
}

interface AuthorityRepository extends JpaRepository<Authority, Long> {
		Authority findByAuthority(String a);
}

@Service("authz")
class AuthService {

		public boolean check(Message msg, User user) {
				return msg.getTo().getId().equals(user.getId());
		}
}

interface MessageRepository extends JpaRepository<Message, Long> {

		String QUERY = "select m from Message m where m.id = ?1";

		@Query(QUERY)
		@PostAuthorize("@authz.check( returnObject , principal?.user  )")
		Message findByIdBeanCheck(Long id);

		@RolesAllowed("ROLE_ADMIN")
		@Query(QUERY)
		Message findByIdRolesAllowed(Long id);

		@Secured("ROLE_ADMIN")
		@Query(QUERY)
		Message findByIdSecured(Long id);

		@PreAuthorize("hasRole('ADMIN')")
		@Query(QUERY)
		Message findByIdPreAuthorize(Long id);

		@Query("select m from Message m where m.to.id = ?#{ principal?.user?.id }")
		Page<Message> findMessagesFor(Pageable pageable);
}

@Data
@AllArgsConstructor
@ToString(exclude = "users")
@Entity
@EqualsAndHashCode(exclude = "users")
class Authority {

		@Id
		@GeneratedValue
		private Long id;

		private String authority;

		Authority() {
		}

		Authority(String authority) {
				this(authority, new HashSet<>());
		}

		Authority(String authority, Set<User> users) {
				this.authority = authority;
				this.users.addAll(users);
		}

		@ManyToMany(cascade = {
			CascadeType.PERSIST,
			CascadeType.MERGE
		})
		@JoinTable(name = "authority_user",
			joinColumns = @JoinColumn(name = "authority_id"),
			inverseJoinColumns = @JoinColumn(name = "user_id")
		)
		private List<User> users = new ArrayList<>();

}


@Data
@AllArgsConstructor
@EqualsAndHashCode(exclude = "authorities")
@Entity
class User {

		@Id
		@GeneratedValue
		private Long id;
		private String email;
		private String password;

		@ManyToMany(mappedBy = "users")
		private List<Authority> authorities = new ArrayList<>();

		User() {
				this(null, null, new HashSet<>());
		}

		User(String u, String pw, Set<Authority> authorities) {
				this.email = u;
				this.password = pw;
				this.authorities.addAll(authorities);
		}

		User(String u, String pw, Authority... auths) {
				this(u, pw, new HashSet<>(Arrays.asList(auths)));
		}

		User(String e, String pw) {
				this(e, pw, new HashSet<>());
		}
}

@Entity
@Data
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
class Message {

		@Id
		@GeneratedValue
		private Long id;

		private String text;

		@OneToOne
		private User to;

		@LastModifiedDate
		private Date lastModifiedDate;

		@CreatedDate
		private Date createdDate;

		@LastModifiedBy
		private String lastModifiedBy;

		@CreatedBy
		private String createdBy;

		Message() {
		}

		public Message(String text, User to) {
				this.text = text;
				this.to = to;
		}
}


@Service
class UserRepositoryUserDetailsService implements UserDetailsService {

		private final UserRepository users;

		public UserRepositoryUserDetailsService(UserRepository users) {
				this.users = users;
		}

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				User user = users.findByEmail(username);
				if (null == user) {
						throw new UsernameNotFoundException("can't find " + username + "!");
				}
				return new CustomUserDetails(user);
		}

		@ToString
		static final class CustomUserDetails implements UserDetails {

				private final User user;

				private final Collection<GrantedAuthority> authorities;

				CustomUserDetails(User user) {
						this.user = user;
						this.authorities = this.user.getAuthorities()
							.stream()
							.map(au -> new SimpleGrantedAuthority("ROLE_" + au.getAuthority()))
							.collect(Collectors.toSet());
				}

				@Override
				public Collection<? extends GrantedAuthority> getAuthorities() {
						return this.authorities;
				}

				@Override
				public String getPassword() {
						return this.user.getPassword();
				}

				public User getUser() {
						return user;
				}

				@Override
				public String getUsername() {
						return user.getEmail();
				}

				@Override
				public boolean isAccountNonExpired() {
						return true;
				}

				@Override
				public boolean isAccountNonLocked() {
						return true;
				}

				@Override
				public boolean isCredentialsNonExpired() {
						return true;
				}

				@Override
				public boolean isEnabled() {
						return true;
				}
		}
}
