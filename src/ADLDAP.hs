module ADLDAP (adInit, adSearch) where

import LDAP
import ADLDAP.Types
import ADLDAP.Utils

adInit :: Realm -> Host -> Port -> IO ADCtx
adInit r h p = do
  ldap <- ldapInit h (fromIntegral p)
  ldapGSSAPISaslBind ldap
  m <- fetchAllTypes ldap r
  return $ ADCtx r h p ldap m
