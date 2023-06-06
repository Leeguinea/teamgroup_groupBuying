package com.example.GroupBuying.service;

//테스트용 주석

import com.example.GroupBuying.dto.MemberDTO;
import com.example.GroupBuying.entity.MemberEntity;
import com.example.GroupBuying.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service //스프링이 관리해주는 객체로 등록
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    
    //회원가입
    public void save(MemberDTO memberDTO) { //Controller로 부터 DTO 객체를 받은 save 메소드
        // 조건. entity 객체를 DB로 넘겨주어한다.)
        // (1) dto -> entity 객체로 변환 ---> Entity 클래스에서 작업해준다.
        MemberEntity memberEntity = MemberEntity.toMemberEntity(memberDTO); //memberDTO 객체를 넘겨주면서, Entity 의 toMemberEntity 클래스를 호출(객체 변환 실행)
        // (2) entity 객체를 넘겨줄 repository의 save메소드 호출
        memberRepository.save(memberEntity); //repository의 save 메소드 호출(Entity 객체를 넘겨주면서)
    }

    public MemberDTO login(MemberDTO memberDTO) {
        /*
            1. 회원이 입력한 아이디를 DB에서 조회함.
            2. 위의 1번이 일치하다면 -> 사용자가 입력한 비밀번호와 DB에서 조회한 비밀번호가 일치하는지 판단.
         */

        Optional<MemberEntity> byId = memberRepository.findById(memberDTO.getId()); //엔티티 객체를 Optional로 감싼 상태
        MemberEntity memberEntity;
        if (byId.isPresent()) {
            //
            // 조회 결과, 해당 Id를 가진 회원정보가 DB에 있다. (비번은 아직 확인 안한 상태)
            memberEntity = byId.get();
            if (memberEntity.getPwd().equals(memberDTO.getPwd())) {
                //비밀번호가 일치하는 경우 -> Entity를 DTO로 변환해서 Controller로 전달해준다.
                MemberDTO dto = MemberDTO.toMemberDTO(memberEntity);
                return dto;
            } else {
                //비밀번호가 불일치(로그인 실패)
                return new MemberDTO(10); // 비밀번호가 불일치할 때 10을 반환하는 MemberDTO 객체 생성
            }
        } else {
            // 조회 결과가 없다.
            return new MemberDTO(20); // ID가 불일치할 때 20을 반환하는 MemberDTO 객체 생성
        }

    }





    public List<MemberDTO> findALL() {
        List<MemberEntity> memberEntityList = memberRepository.findAll();
        //Entity가 여러개 담긴 List를 DTO가 여러개 담긴 List로 변환
        List<MemberDTO> memberDTOList = new ArrayList<>();
        for (MemberEntity memberEntity: memberEntityList) {
            memberDTOList.add(MemberDTO.toMemberDTO(memberEntity));
            MemberDTO memebrDTO = MemberDTO.toMemberDTO(memberEntity);
            memberDTOList.add(memebrDTO);
        }
        return memberDTOList;
    }

    public MemberDTO findById(String id) {
        Optional<MemberEntity> optionalMemberEntity = memberRepository.findById(id);
        if (optionalMemberEntity.isPresent()) {
            return MemberDTO.toMemberDTO(optionalMemberEntity.get());
        } else {
            return null;
        }
    }


    public MemberDTO updateForm(String myId) { //Id로 DB에서 회원정보를 조회하는것.
        Optional<MemberEntity> optionalMemberEntity = memberRepository.findById(myId);
        if(optionalMemberEntity.isPresent()) {
            return MemberDTO.toMemberDTO(optionalMemberEntity.get());
        } else {
            return null;
        }
    }

    public void update(MemberDTO memberDTO) {
        memberRepository.save(MemberEntity.toUpdateMemberEntity(memberDTO));
    }



    public String idCheck(String id) {
        Optional<MemberEntity> byId = memberRepository.findById(id);
        if (byId.isPresent()) {
            //조회결과가 있다 -> 해당 아이디는 사용 불가
            return null;

        } else {
            //조회결과가 없다. -> 사용할 수 있다.
            return "ok";
        }

    }

    public MemberEntity findByMyId(String loginId) {
        return memberRepository.findById(loginId).get();
    }

    public void update(MemberDTO memberDTO,String loginId){
        MemberEntity memberEntity=memberRepository.findById(loginId).get();

        if (memberDTO.getPwd().equals(memberEntity.getPwd())) {
            if(memberDTO.getNewPwd().equals(memberDTO.getConfirmPwd())){
              memberEntity.setNickname(memberDTO.getNickname());
              memberEntity.setPwd(memberDTO.getNewPwd());
              memberRepository.save(memberEntity);
            } else {
                throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
            }
        } else {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
    }
    @Transactional
    public void deleteById(String id) {
        memberRepository.deleteById(id);
    }
}

