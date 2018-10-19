package com.example.methodsecurity;

import lombok.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
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

@EnableJpaAuditing
@EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = true, securedEnabled = true)
@SpringBootApplication
public class MethodSecurityApplication {

	@Bean
	AuditorAware<String> auditor() {
		return () -> {
			SecurityContext context = SecurityContextHolder.getContext();
			Authentication authentication = context.getAuthentication();
			if (null != authentication) {
				return Optional.ofNullable(authentication.getName());
			}
			return Optional.empty();
		};
	}

	@Bean
	SecurityEvaluationContextExtension securityEvaluationContextExtension() {
		return new SecurityEvaluationContextExtension();
	}

	public static void main(String[] args) {
		SpringApplication.run(MethodSecurityApplication.class, args);
	}

}

@Transactional
@Component
@Log4j2
class Runner implements ApplicationRunner {

	private final UserRepository userRepository;

	private final AuthorityRepository authorityRepository;

	private final MessageRepository messageRepository;

	private final UserDetailsService userDetailsService;

	Runner(UserRepository userRepository, AuthorityRepository authorityRepository,
			MessageRepository messageRepository, UserDetailsService userDetailsService) {
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.messageRepository = messageRepository;
		this.userDetailsService = userDetailsService;
	}

	private void authenticate(String username) {
		UserDetails user = this.userDetailsService.loadUserByUsername(username);
		Authentication authentication = new UsernamePasswordAuthenticationToken(user,
				user.getPassword(), user.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
		// install some data
		Authority user = this.authorityRepository.save(new Authority("USER")),
				admin = this.authorityRepository.save(new Authority("ADMIN"));

		User josh = this.userRepository.save(new User("josh", "password", user));
		User rob = this.userRepository.save(new User("rob", "password", admin, user));

		Message messageForRob = this.messageRepository.save(new Message("hi Rob!", rob));
		this.messageRepository.save(new Message("Hi 1", rob));
		this.messageRepository.save(new Message("Hi 2", rob));

		this.messageRepository.save(new Message("Hi 1", josh));

		log.info("josh: " + josh.toString());
		log.info("rob: " + rob.toString());

		attemptAccess(rob.getEmail(), josh.getEmail(), messageForRob.getId(),
				this.messageRepository::findByIdRolesAllowed);

		attemptAccess(rob.getEmail(), josh.getEmail(), messageForRob.getId(),
				this.messageRepository::findByIdSecured);

		attemptAccess(rob.getEmail(), josh.getEmail(), messageForRob.getId(),
				this.messageRepository::findByIdPreAuthorize);

		attemptAccess(rob.getEmail(), josh.getEmail(), messageForRob.getId(),
				this.messageRepository::findByIdPostAuthorize);

		authenticate(rob.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(log::info);

		authenticate(josh.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(log::info);

		log.info("audited: "
				+ this.messageRepository.save(new Message("this is a test", rob)));

	}

	private void attemptAccess(String adminUser, String regularUser, Long msgId,
			Function<Long, Message> fn) {
		authenticate(adminUser);
		log.info("result for Rob:" + fn.apply(msgId));

		try {
			authenticate(regularUser);
			log.info("result for Josh:" + fn.apply(msgId));
		}
		catch (Throwable e) {
			log.error("oops! couldn't obtain the result for Josh");
		}

	}

}

@Service
class UserRepositoryUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	UserRepositoryUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	public static class UserUserDetails implements UserDetails {

		private final User user;

		private final Set<GrantedAuthority> authorities;

		public UserUserDetails(User user) {
			this.user = user;
			this.authorities = this.user.getAuthorities().stream()
					.map(au -> new SimpleGrantedAuthority("ROLE_" + au.getAuthority()))
					.collect(Collectors.toSet());
		}

		public User getUser() {
			return user;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public String getPassword() {
			return this.user.getPassword();
		}

		@Override
		public String getUsername() {
			return this.user.getEmail();
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

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		User usr = this.userRepository.findByEmail(username);
		if (null != usr) {
			return new UserUserDetails(usr);
		}
		else
			throw new UsernameNotFoundException("couldn't find " + username + "!");
	}

}

interface MessageRepository extends JpaRepository<Message, Long> {

	String QUERY = "select m from Message m where m.id = ?1";

	@Query(QUERY)
	@RolesAllowed("ROLE_ADMIN")
	Message findByIdRolesAllowed(Long id);

	@Query(QUERY)
	@Secured("ROLE_ADMIN")
	Message findByIdSecured(Long id);

	@Query(QUERY)
	@PreAuthorize("hasRole('ADMIN')")
	Message findByIdPreAuthorize(Long id);

	@Query(QUERY)
	@PostAuthorize("@authz.check(returnObject, principal?.user )")
	Message findByIdPostAuthorize(Long id);

	@Query("select m from Message m where m.to.id = ?#{  principal?.user?.id  }")
	Page<Message> findMessagesFor(Pageable pageable);

}

@Log4j2
@Service("authz")
class AuthService {

	public boolean check(Message msg, User user) {
		log.info("checking " + user.getEmail() + "..");
		return msg.getTo().getId().equals(user.getId());
	}

}

interface UserRepository extends JpaRepository<User, Long> {

	User findByEmail(String email);

}

interface AuthorityRepository extends JpaRepository<Authority, Long> {

}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@EntityListeners(AuditingEntityListener.class)
class Message {

	@Id
	@GeneratedValue
	private Long id;

	private String text;

	@OneToOne
	private User to;

	@CreatedBy
	private String createdBy;

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	private Date created;

	public Message(String text, User to) {
		this.text = text;
		this.to = to;
	}

}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(exclude = "authorities")
@Data
class User {

	@Id
	@GeneratedValue
	private Long id;

	private String email, password;

	@ManyToMany(mappedBy = "users")
	private List<Authority> authorities = new ArrayList<>();

	public User(String email, String password, Set<Authority> authorities) {
		this.email = email;
		this.password = password;
		this.authorities.addAll(authorities);
	}

	public User(String email, String password) {
		this(email, password, new HashSet<>());
	}

	public User(String email, String password, Authority... authorities) {
		this(email, password, new HashSet<>(Arrays.asList(authorities)));
	}

}

@Entity
@AllArgsConstructor
@ToString(exclude = "users")
@NoArgsConstructor
@Data
class Authority {

	@Id
	@GeneratedValue
	private Long id;

	private String authority;

	public Authority(String authority) {
		this.authority = authority;
	}

	public Authority(String authority, Set<User> users) {
		this.authority = authority;
		this.users.addAll(users);
	}

	@ManyToMany(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinTable(name = "authority_user", joinColumns = @JoinColumn(name = "authority_id"), inverseJoinColumns = @JoinColumn(name = "user_id"))
	private List<User> users = new ArrayList<>();

}
