package com.exp.repository;

import com.exp.domain.AuthCode;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Created by rohith on 20/2/18.
 */
@Repository
public interface AuthCodeRepository extends CrudRepository<AuthCode, Long>{

    AuthCode findByAuthorizationCode(String authorizationCode);

}
