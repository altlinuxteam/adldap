{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module ADLDAP.Utils (adSearch, fetchAllTypes) where

import ADLDAP.Types
import qualified Data.ByteString.Char8 as BC
import qualified Data.Map as M
import qualified Data.Set as S
import LDAP.Search
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.List as L
import Data.Maybe (fromJust)
import qualified Data.Text as T
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ASN1.Encoding as Asn
import qualified Data.ASN1.BinaryEncoding as Asn
import qualified Data.ASN1.Types as Asn
import qualified Data.Map as M
import GHC.Word
import LDAP

--import Debug.Trace

adSearch :: ADCtx -> DN -> Scope -> Maybe Filter -> [Key] -> IO [Record]
adSearch ad@ADCtx{..} dn scope filter attrs = do
  res <- ldapSearch ldap dn' scope' filter' attrs' False
  return $ map (le2r ad) res
  where dn' = Just $ T.unpack $ unTag dn
        scope' = lscope scope
        filter' = (T.unpack . unTag) <$> filter
        attrs' = lattrs attrs

le2r :: ADCtx -> LDAPEntry -> Record
le2r ad (LDAPEntry ledn leattrs) = Record dn attrs
  where attrs = M.fromList $ map (la2a ad) leattrs
        dn = Tagged $ T.pack ledn

la2a :: ADCtx -> (String, [String]) -> (Key, Attr)
la2a ADCtx{..} (k, vs) = (key, attr)
  where key = Tagged (T.pack k)
        attr = Attr atype vs'
        atype = case M.lookup key tmap of
                  Just x -> x
                  Nothing -> error $ k ++ " not found in types database"
        vs' = S.fromList $ map BC.pack vs

lscope :: Scope -> LDAPScope
lscope Base = LdapScopeBase
lscope One = LdapScopeOnelevel
lscope Sub = LdapScopeSubtree

lattrs :: [Key] -> SearchAttributes
lattrs [] = LDAPNoAttrs
lattrs as = LDAPAttrList $ map (T.unpack . unTag) as

r2dnS :: Realm -> String
r2dnS = T.unpack . unTag . realm2dn

realm2dn :: Realm -> DN
realm2dn r = Tagged $ T.concat ["DC=", T.replace "." ",DC=" r]

fetchAllTypes :: LDAP -> Realm -> IO TypeMap
fetchAllTypes ldap adRealm = do
  res <- ldapSearch ldap (Just dn) (lscope Sub) (Just "(objectClass=attributeSchema)") attrs False
  return $ M.fromList $ map (\(n, oid) -> (Tagged (T.pack n), fromJust (fromOID oid))) $ keys res
  where dn = "CN=Schema,CN=Configuration," <> dn'
        dn' = r2dnS adRealm
        attrs = LDAPAttrList ["lDAPDisplayName", "attributeSyntax", "oMSyntax", "oMObjectClass"]
        keys = map (\(LDAPEntry _ vs) ->
                       let name = head $ fromJust $ L.lookup "lDAPDisplayName" vs
                           as = head $ fromJust $ L.lookup "attributeSyntax" vs
                           oms :: Int
                           oms = read $ head $ fromJust $ L.lookup "oMSyntax" vs
                           omo = case oms of
                                   127 -> oMObjectClassFromBER $ BC.pack $ head $ fromJust $ L.lookup "oMObjectClass" vs
                                   _ -> Nothing
                       in  (name, (as, oms, omo))
          )
        t r = case oMObjectClassFromBER r of
                Just x -> x
                Nothing -> error $ "cannot decode " ++ (show r)

oMObjectClassFromBER :: ByteString -> Maybe String
oMObjectClassFromBER hex = case Asn.decodeASN1' Asn.BER hex' of
  Right [Asn.OID x] -> Just $ stringify x
  Left _ -> Nothing
  where hex' = if 0x06 == BS.head hex then hex else 0x06 `BS.cons` (BS.pack [len]) <> hex
        len = fromIntegral (BS.length hex) :: Word8
        stringify = L.init . L.foldr (\a b -> show a <> "." <> b) ""
