package com.exp.repository;

import com.exp.domain.Client;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Created by rohith on 19/2/18.
 */
@Repository
public interface ClientRepository extends CrudRepository<Client, String> {

}
