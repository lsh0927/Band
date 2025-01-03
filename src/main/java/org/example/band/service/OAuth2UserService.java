package org.example.band.service;

import org.example.band.config.UserPrincipal;
import org.example.band.entity.User;
import org.example.band.enums.Provider;
import org.example.band.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

	private final UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest)
		throws OAuth2AuthenticationException {
		OAuth2User oauth2User = super.loadUser(userRequest);

		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		String providerId = oauth2User.getAttribute("id");
		String email = oauth2User.getAttribute("email");
		String name = oauth2User.getAttribute("name");
		String profileImage = oauth2User.getAttribute("profile_image");

		User user = userRepository.findByEmailAndProvider(email,
				Provider.valueOf(registrationId.toUpperCase()))
			.orElseGet(() -> createUser(email, name, profileImage,
				Provider.valueOf(registrationId.toUpperCase()), providerId));

		return UserPrincipal.create(user, oauth2User.getAttributes());
	}

	private User createUser(String email, String name, String profileImage,
		Provider provider, String providerId) {
		User user = User.builder()
			.email(email)
			.name(name)
			.profileImage(profileImage)
			.provider(provider)
			.providerId(providerId)
			.build();

		return userRepository.save(user);
	}
}