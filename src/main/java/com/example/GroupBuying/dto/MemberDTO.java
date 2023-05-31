package com.example.GroupBuying.dto;

import com.example.GroupBuying.entity.MemberEntity;
import lombok.*; // lombok 라이브러리는 클래스에 어노테이션만 붙여주면, 클래스내의 각 필드의 메소드를 생성해준다.

@Getter
@Setter
@AllArgsConstructor //모든 필드를 매개변수로 하는 생성자를 만들어준다.
@Builder
@ToString // DTO 객체가 가지고 있는 필드값을 출력할 때 메소드를 생성해준다.
public class MemberDTO { //DTO 클래스는 회원정보에 필요한 내용들을 필드로 정리하고, 접근제한자 private 으로 필드를 감춘다. -> Getter & Setter로만 간접적으로 사용가능하게 한다.
    private int resultCode;
    private int errorCode;
    // 생성자
    public MemberDTO(int resultCode) {
        this.resultCode = resultCode;
    }
    // 추가 생성자
    public MemberDTO(int resultCode, int errorCode) {
        this.resultCode = resultCode;
        this.errorCode = errorCode;
    }
    // getter/setter
    public int getResultCode() {
        return resultCode;
    }
    public void setResultCode(int resultCode) {
        this.resultCode = resultCode;
    }
    public int getErrorCode() {
        return errorCode;
    }
    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    // 기본 생성자 추가
    public MemberDTO() {
        // 기본 생성자
    }


    private Long number;//추가
    private String id;
    private String nickname;
    private String pwd;
    private String name;
    private String phone1;
    private String phone2;
    private String phone3;
    private String year;
    private String month;
    private String day;
    private String confirmPwd;
    private String newPwd;

    public static MemberDTO toMemberDTO(MemberEntity memberEntity){
        MemberDTO memberDTO = new MemberDTO();
        memberDTO.setId(memberEntity.getId());
        memberDTO.setNickname(memberEntity.getNickname());
        memberDTO.setPwd(memberEntity.getPwd());
        memberDTO.setName(memberEntity.getName());
        memberDTO.setPhone1(memberEntity.getPhone1());
        memberDTO.setPhone2(memberEntity.getPhone2());
        memberDTO.setPhone3(memberEntity.getPhone3());
        memberDTO.setYear(memberEntity.getYear());
        memberDTO.setMonth(memberEntity.getMonth());
        memberDTO.setDay(memberEntity.getDay());
        return memberDTO;

    }

}