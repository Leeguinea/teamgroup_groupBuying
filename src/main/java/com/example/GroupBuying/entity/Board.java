package com.example.GroupBuying.entity;

import lombok.*;

import javax.persistence.*;
import java.lang.reflect.Member;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static javax.persistence.FetchType.EAGER;
import static javax.persistence.FetchType.LAZY;

@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Entity
public class Board {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "board_id")
    private Long id;
    private String title;
    private String recruitment;
    private String item;
    private String content;
    private String category;
    @Column(name = "writer_id")
    private String writer;
    private String link;
    private LocalDateTime datetime;
    private LocalDate date;
    private int fileAttached; // 1이면 첨부, 0이면 없음

    @ManyToOne(fetch = EAGER)
    @JoinColumn(name = "member_number")
    private MemberEntity member;

    @OneToMany(mappedBy = "board", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<BoardFile> boardFileList = new ArrayList<>();

    public void setMember(MemberEntity member){
        this.member=member;
        member.getBoardList().add(this);
    }
}