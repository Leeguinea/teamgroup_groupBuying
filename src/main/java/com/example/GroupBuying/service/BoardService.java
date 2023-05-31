package com.example.GroupBuying.service;

import com.example.GroupBuying.dto.BoardDTO;
import com.example.GroupBuying.dto.BoardFileDTO;
import com.example.GroupBuying.entity.Board;
import com.example.GroupBuying.entity.BoardFile;
import com.example.GroupBuying.entity.MemberEntity;
import com.example.GroupBuying.repository.BoardFileRepository;
import com.example.GroupBuying.repository.BoardRepository;
import com.example.GroupBuying.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class BoardService {

    private final BoardRepository boardRepository;
    private final MemberRepository memberRepository;
    private final HttpSession session;
    private final BoardFileRepository boardFileRepository;

    public void write(BoardDTO boardDTO, BoardFileDTO boardFileDTO) throws IOException {

        String loginId = (String) session.getAttribute("loginId");
        Optional<MemberEntity> byMember = memberRepository.findById(loginId);

        MemberEntity member=byMember.get();

        Board board = Board.builder()
                .id(boardDTO.getId())
                .title(boardDTO.getTitle())
                .item(boardDTO.getItem())
                .category(boardDTO.getCategory())
                .content(boardDTO.getContent())
                .recruitment(boardDTO.getRecruitment())
                .datetime(LocalDateTime.now())
                .date(LocalDate.now())
                .writer(loginId)
                .link(boardDTO.getLink())
                .member(member)
                .fileAttached(boardFileDTO.getBoardFile()== null || boardFileDTO.getBoardFile().isEmpty() ? 0 : 1)
                .build();
        Long saveId=boardRepository.save(board).getId(); // 현재 저장하는 게시물 id를 가져옴

        String savePath =null;
        if(boardFileDTO.getBoardFile() !=null && !boardFileDTO.getBoardFile().isEmpty()) {
            //첨부파일이 있음

            MultipartFile boardFile = boardFileDTO.getBoardFile();
            String originalFileName = boardFile.getOriginalFilename();
            String storedFileName = System.currentTimeMillis()+ '_' +originalFileName;

            savePath = "C:/temp/"+storedFileName;

            //C:/temp/디렉토리가 존재하지 않는다면 생성
            File dir = new File("C:/temp/");
            if(!dir.exists()) {
                dir.mkdir();
            }

            boardFile.transferTo(new File(savePath));

            BoardFile toboardFile = BoardFile.builder()
                    .originalFileName(originalFileName)//여기서 생성한 값
                    .board(board) //연관관계가 된 board 값
                    .storedFileName(storedFileName)//여기서 생성한 값
                    .boardTime(board.getDatetime())//board의 작성 시간
                    .build();
            System.out.println("storedFileName = " + storedFileName);

            boardFileRepository.save(toboardFile);
        }
    }
    public List<Board> findAll() {
        return boardRepository.findAll();
    }


    public List<Board> searchKeyList(String searchKey) {
        return boardRepository.findByTitleContainingIgnoreCaseOrderByIdDesc(searchKey);
    }

    public List<Board> findByWriter(String loginId) {
        System.out.println("loginId = " + loginId);
        return boardRepository.findByWriter(loginId);
    }

    public Board findById(Long id) {
        return boardRepository.findById(id).get();
    }

    public List<Board> findAllByOrderByidDesc() {
        return boardRepository.findAllByOrderByIdDesc();
    }

}