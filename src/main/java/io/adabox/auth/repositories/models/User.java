package io.adabox.auth.repositories.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@Getter
@Setter
@ToString
@Table(name = "users")
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(max = 64)
	@Column(name = "stake_key", nullable = false)
	private String stakeKey;

	@NotBlank
	@Size(max = 108)
	@Column(name = "wallet_address", nullable = false)
	private String walletAddress;

	@Email
	@Size(max = 64)
	@Column(name = "email")
	private String email;

	@JsonIgnore
	@Column(columnDefinition = "boolean default false",name = "email_verified")
	private boolean isEmailVerified;

	@NotBlank
	@Size(max = 50)
	@Column(name = "username", nullable = false)
	private String username;

	@Column(columnDefinition = "varchar(2) default 'en'", name = "preferred_language")
	private String preferredLanguage;

	@Size(max = 250)
	@Column(name = "bio")
	private String bio;

	@Size(max = 250)
	@Column(name = "image_url")
	private String imageUrl;

	@Size(max = 250)
	@Column(name = "cover_url")
	private String coverUrl;

	@Size(max = 15)
	@Column(name = "twitter")
	private String twitter;

	@Size(max = 30)
	@Column(name = "instagram")
	private String instagram;

	@Size(max = 39)
	@Column(name = "github")
	private String github;

	@Size(max = 24)
	@Column(name = "youtube")
	private String youtube;

	@Size(min = 4, max = 24)
	@Column(name = "twitch")
	private String twitch;

	@Size(max = 128)
	@Column(name = "facebook")
	private String facebook;

	@Size(max = 250)
	@Column(name = "website")
	private String website;

	@Column(name = "created_date", nullable = false, updatable = false)
	@Temporal(TemporalType.TIMESTAMP)
	protected Date createdDate;

	@JsonIgnore
	@Column(name = "modified_date")
	@Temporal(TemporalType.TIMESTAMP)
	protected Date modifiedDate;

	@JsonIgnore
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(	name = "user_roles",
			joinColumns = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();

	@JsonIgnore
	@Column(columnDefinition = "boolean default false")
	private boolean banned;
}