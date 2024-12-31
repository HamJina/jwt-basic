package com.example.SpringJWT.service;

import com.example.SpringJWT.dto.JoinDTO;
import com.example.SpringJWT.entity.UserEntity;
import com.example.SpringJWT.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    //비밀번호 암호화
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        //username이 이미 존재하는 이름인지 판단
        Boolean isExist = userRepository.existsByUsername(username);

        //이미 존재하는 이름이면 회원가입 진행x
        if (isExist) {
            return;
        }

        //존재하지 않는 이름이면 새로운 User엔티티 생성
        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); //인코딩된 비밀번호 설정
        data.setRole("ROLE_ADMIN");

        //user객체 저장
        userRepository.save(data);
    }
}