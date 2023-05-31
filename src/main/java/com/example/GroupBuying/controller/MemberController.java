package com.example.GroupBuying.controller;

import com.example.GroupBuying.dto.MemberDTO;
import com.example.GroupBuying.entity.Board;
import com.example.GroupBuying.entity.MemberEntity;
import com.example.GroupBuying.service.BoardService;
import com.example.GroupBuying.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpSession;
import java.util.List;


@Controller //MemberController 를 스프링 객체로 등록해주는 어노테이션
@RequiredArgsConstructor
public class MemberController {
    //생성자 주입
    private final MemberService memberService;
    private final BoardService boardService;

    //회원가입 페이지 출력 요청
    @GetMapping("/GroupBuying/join") //해당 링크를 받으면, 아래 메소드 실행
    public String saveForm() {
        return "join"; //스프링이 templates 폴더에서, join.html 파일을 찾는다. -> 브라우저에 띄워준다.
    }

    //join.html 에서 작성한 회원가입 내용을 받아주는 메소드
    // post 방식으로 데이터를 보냈기 때문에 Postmapping 어노테이션을 사용해서 데이터를 받는다.
    @PostMapping("/GroupBuying/join")
    public String save(@ModelAttribute MemberDTO memberDTO) {  //회원가입에 필요한 정보를 DTO 객체로 받아왔다. (from join.html파일)
        System.out.println("memberDTO = " + memberDTO);
        memberService.save(memberDTO); //memberService 객체의 save 메소드를 호출하면서 동시에 DTO 객체를 넘겼다.
        return "login";
    }

    @GetMapping("/GroupBuying/login")  //주소 요청이 왔을때, 로그인 페이지를 띄워주자.
    public String loginForm() {
        return "login";
    }

    @PostMapping("/GroupBuying/login")
    public String login(@ModelAttribute MemberDTO memberDTO, HttpSession session, Model model, String searchKey) {
        MemberDTO loginResult = memberService.login(memberDTO);
        if (loginResult != null && loginResult.getResultCode() == 10) {
            // 비밀번호 불일치시
            return "login_pwd_fail";
        } else if (loginResult != null && loginResult.getResultCode() == 20) {
            // ID 불일치시
            return "login_id_fail";
        } else {
            // 로그인 성공시 -> 게시글 창 띄어짐
            session.setAttribute("loginId", loginResult.getId());
            List<Board> boardList = null;
            if(searchKey==null) {
                boardList = boardService.findAllByOrderByidDesc();
            } else {
                boardList = boardService.searchKeyList(searchKey);
            }
            model.addAttribute("boardList", boardList);
            return "gesi";
        }
    }

    @PostMapping("/GroupBuying/login_id_fail")
    public String loginIdFailRedirect(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("login_id_fail", true);
        return "redirect:/GroupBuying/login";
    }

    @PostMapping("/GroupBuying/login_pwd_fail")
    public String loginPwdFailRedirect(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("login_pwd_fail", true);
        return "redirect:/GroupBuying/login";
    }

    @GetMapping("/GroupBuying/") //전체 회왼정보 조회 // DB에 저장된 회원데이터를 모두 가져온다.
    public String findAll(Model model) { //model 이라는 스프링에서 제공해주는 객체를 이용.
        List<MemberDTO> memberDTOList = memberService.findALL();
        // 어떠한 HTML로 가져갈 데이터가 있다면, model을 사용.
        model.addAttribute("memberList", memberDTOList);
        return "list";
    }

    @GetMapping("/GroupBuying/{id}")  //회원정보 상세조회
    public String findById(@PathVariable String id, Model model) {
        MemberDTO memberDTO = memberService.findById(id); //내가 조회하는 데이터가 1명일때는 DTO로 리턴 타입을 정한다.
        model.addAttribute("member", memberDTO);
        return "detail";
    }

    @GetMapping("/logout") //로그아웃
    public String logout(HttpSession session){
        session.invalidate();
        return "home";
    }

    @GetMapping("/mypage")
    public String mypage(Model model, HttpSession session) {
        List<Board> myboardList = null;
        String loginId = (String) session.getAttribute("loginId"); // 세션에서 아이디를 가져옴

        MemberEntity myMemberList=memberService.findByMyId(loginId);
        myboardList = boardService.findByWriter(loginId); // 로그인 아이디로 작성자가 일치하는 게시물을 가져옴
        model.addAttribute("boardList",myboardList);
        model.addAttribute("memberList",myMemberList);
       return "mypage";
    }


    @GetMapping("/mypage/information_change")
    public String updateForm(HttpSession session, Model model) {
        String myId = (String) session.getAttribute("loginId");
        MemberDTO memberDTO = memberService.updateForm(myId); //myId로 조회해서 DTO에 가져온다.
        model.addAttribute("updateMember", memberDTO);//model에 담아서 아래 HTML 로 간다.
        return "information_change";
    }

    @PostMapping("/mypage/information_change")  //사용자가 입력한 값을 받아오는 컨트롤러
    public String update(@ModelAttribute MemberDTO memberDTO) {
        memberService.update(memberDTO); //서비스의 업데이트 메소드 호출
        return "redirect:/GroupBuying/" + memberDTO.getId();
    }

    @PostMapping("/GroupBuying/id-check")
    public @ResponseBody String idCheck(@RequestParam("id") String id) {
        System.out.println("id = " + id);
        String checkResult = memberService.idCheck(id);
        return checkResult;
    }

    @GetMapping("/information_change")
    public String changForm(Model model, HttpSession session){
        String loginId = (String) session.getAttribute("loginId"); // 세션에서 아이디를 가져옴
        MemberEntity memberEntity = memberService.findByMyId(loginId);
        model.addAttribute("member",memberEntity);
        return "update";
    }

    @PostMapping("/information_change")
    public String change(MemberDTO memberDTO,HttpSession session){
        String loginId = (String) session.getAttribute("loginId"); // 세션에서 아이디를 가져옴
        memberService.update(memberDTO,loginId);
        return "redirect:/";
    }

    //회원탈퇴 구현
    @GetMapping("/withdrawal")
    public String withdrawalForm() {
        return "withdrawal";
    }

    @PostMapping("/withdrawal")
    public String delete(@RequestParam("id") String id) {
        memberService.deleteById(id);
        return "redirect:/logout";
    }

}

