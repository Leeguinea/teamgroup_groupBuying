package com.example.GroupBuying.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class BoardDTO {

    private Long id;
    private String title;
    private String recruitment;
    private String item;
    private String content;
    private String category;
    private String link;
    private int fileAttached;
    private BoardFileDTO boardFileDTO;
}
