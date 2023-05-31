package com.example.GroupBuying.repository;

import com.example.GroupBuying.entity.Board;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BoardRepository extends JpaRepository<Board, Long> {
    List<Board> findByWriter(String loginId);

    List<Board> findByTitleContainingIgnoreCaseOrderByIdDesc(String searchKey);

    List<Board> findAllByOrderByIdDesc();

    List<Board> findByTitleContaining(String searchKey);
}
