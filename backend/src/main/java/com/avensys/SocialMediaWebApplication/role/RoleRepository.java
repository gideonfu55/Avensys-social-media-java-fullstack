package com.avensys.SocialMediaWebApplication.role;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer>  {

  Role findRolesByName(String name);
}
