package com.example.GroupBuying.entity;

import com.example.GroupBuying.dto.MemberDTO;
import lombok.*;
import lombok.Getter;
import lombok.Setter;


import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity //스프링 데이터 JPA 는 Entity 클래스를 이용해서 데이터베이스의 테이블을 -> 자바의 객체처럼 활용할 수 있게 한다.
@Setter
@Getter
@Table(name = "member_table")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberEntity {
    @Id // pk 지정
    @GeneratedValue(strategy = GenerationType.IDENTITY) //auto_increment -> auto_increment 는 MySQL에서 자동으로 증가하는 일련번호를 생성할 때 사용되는 키워드
    @Column(name = "member_number")
    private Long number;

    @Column
    private String pwd;

    @Column
    private String nickname;

    @Column
    private String name;

    @Column
    private String phone1,phone2,phone3;

    @Column
    private String month;

    @Column
    private String year;

    @Column
    private String day;

    @Column //unique 제약 조건 추가
    private String id;

    @OneToMany(mappedBy = "member")
    private List<Board> boardList=new ArrayList<>();

    public static MemberEntity toMemberEntity(MemberDTO memberDTO) {  // toMemberEntity 클래스 메소드 선언
        MemberEntity memberEntity = new MemberEntity(); //객체선언
        memberEntity.setId(memberDTO.getId()); //memeberDTO 객체의 getID 메소드로 부터 값을 얻어서, setID 메소드로 ID값을 설정
        memberEntity.setNickname(memberDTO.getNickname());
        memberEntity.setPwd(memberDTO.getPwd());
        memberEntity.setName(memberDTO.getName());
        memberEntity.setPhone1(memberDTO.getPhone1());
        memberEntity.setPhone2(memberDTO.getPhone2());
        memberEntity.setPhone3(memberDTO.getPhone3());
        memberEntity.setYear(memberDTO.getYear());
        memberEntity.setMonth(memberDTO.getMonth());
        memberEntity.setDay(memberDTO.getDay());
        return memberEntity; // 대입된 값들을 다시 service 객체로 반환
    }


    // 이러한 형식을 같는 테이블을 스프링데이터JPA가 DB에서 생성시켜준다.

    public static MemberEntity toUpdateMemberEntity(MemberDTO memberDTO) {  // toMemberEntity 클래스 메소드 선언
        MemberEntity memberEntity = new MemberEntity(); //객체선언
        memberEntity.setId(memberDTO.getId()); //memeberDTO 객체의 getID 메소드로 부터 값을 얻어서, setID 메소드로 ID값을 설정
        memberEntity.setNickname(memberDTO.getNickname());
        memberEntity.setPwd(memberDTO.getPwd());
        memberEntity.setName(memberDTO.getName());
        memberEntity.setPhone1(memberDTO.getPhone1());
        memberEntity.setPhone2(memberDTO.getPhone2());
        memberEntity.setPhone3(memberDTO.getPhone3());
        memberEntity.setYear(memberDTO.getYear());
        memberEntity.setMonth(memberDTO.getMonth());
        memberEntity.setDay(memberDTO.getDay());
        return memberEntity; // 대입된 값들을 다시 service 객체로 반환
    }

}