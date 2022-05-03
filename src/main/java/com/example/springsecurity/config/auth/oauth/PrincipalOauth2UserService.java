package com.example.springsecurity.config.auth.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration: "+userRequest.getClientRegistration()); // registrationId 로 어떤 OAuth 로 로그인 했는 지 파악 가능
        System.out.println("getAccessToken: "+userRequest.getAccessToken().getTokenValue());
        // 구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인을 완료 -> code 를 리턴 (OAuth-Client 라이브러리) -> AccessToken 요청
        // UserRequest 정보 -> loadUser 함수 호출 -> 회원프로필
        System.out.println("userRequest: "+super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        return super.loadUser(userRequest);
    }
}
