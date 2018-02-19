package com.exp.repository;

import com.exp.domain.Role;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Created by rohith on 17/2/18.
 */
@Repository
public interface RoleRepository extends CrudRepository<Role, Long>{
}
