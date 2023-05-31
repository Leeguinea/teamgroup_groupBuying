package com.example.GroupBuying.controller;

import com.example.GroupBuying.dto.BoardDTO;
import com.example.GroupBuying.dto.BoardFileDTO;
import com.example.GroupBuying.entity.Board;
import com.example.GroupBuying.entity.BoardFile;
import com.example.GroupBuying.repository.BoardFileRepository;
import com.example.GroupBuying.service.BoardService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class BoardController {

    private final BoardService boardService;
    private final BoardFileRepository boardFileRepository;

    @GetMapping("/home")
    public String homeForm(){
        return "home";
    }

    @GetMapping("/gesizak")
    public String writeForm(Model model, HttpSession session) {
        if(session.getAttribute("loginId")==null){
            model.addAttribute("message", "로그인 후 사용이 가능합니다.");
            model.addAttribute("searchUrl", "/");
            return "message";
        }
        return "gesi_zak";
    }

    @GetMapping("/gesi")
    public String postForm(Model model, String searchKey){
        List<Board> boardList = null;
        if(searchKey==null) {
            boardList = boardService.findAllByOrderByidDesc();
        } else {
            boardList = boardService.searchKeyList(searchKey);
        }
        model.addAttribute("boardList", boardList);
        return "gesi";
    }

    @GetMapping("/gongi")
    public String noticeForm(){
        return "notice";
    }

    @GetMapping("/jjim")
    public String loveForm(Model model, HttpSession session){
        List<Board> myboardList = null;
        String loginId = (String) session.getAttribute("loginId"); // 세션에서 아이디를 가져옴

        myboardList = boardService.findByWriter(loginId); // 로그인 아이디로 작성자가 일치하는 게시물을 가져옴
        model.addAttribute("boardList",myboardList);
        return "love";
    }

    @PostMapping("/gesizak")
    public String write(BoardDTO boardDTO, BoardFileDTO boardFileDTO, Model model) throws IOException {
        boardService.write(boardDTO, boardFileDTO);
        List<Board> boardList =boardService.findAllByOrderByidDesc();
        model.addAttribute("boardList", boardList);
        return "gesi";
    }

    @GetMapping("/view")
    public String detailForm(Model model, Long id) {
        Board board = boardService.findById(id);
        BoardFile boardFile = boardFileRepository.findByBoard_id(id);

        model.addAttribute("board", board);

        if (boardFile != null && !boardFile.getStoredFileName().isEmpty()) {
            String storedFileName = boardFile.getStoredFileName();
            String imageSrc = "/upload/" + storedFileName;
            model.addAttribute("imageSrc", imageSrc);
        }

        return "snagse_page";
    }
}
