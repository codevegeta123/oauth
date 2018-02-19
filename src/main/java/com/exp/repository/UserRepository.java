package com.exp.repository;

import com.exp.domain.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Created by rohith on 17/2/18.
 */
@Repository
public interface UserRepository  extends CrudRepository<User, Long>{

    User findByUsername(String username);

}
