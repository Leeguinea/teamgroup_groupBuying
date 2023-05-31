package com.example.GroupBuying.dto;

import lombok.*;
import org.springframework.web.multipart.MultipartFile;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class BoardFileDTO {

    private Long id;
    private MultipartFile boardFile;//파일을 담는 용도
    private String originalFileName;// 원본 파일 이름
    private String storedFileName; // 서버 저장용 파일 이름

}
