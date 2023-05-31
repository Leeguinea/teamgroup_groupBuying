package com.example.GroupBuying.repository;

import com.example.GroupBuying.entity.BoardFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BoardFileRepository extends JpaRepository<BoardFile, Long> {
    BoardFile findByBoard_id(Long boardId);
}
