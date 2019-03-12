{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module ADLDAP.Utils (adSearch, adSearchReq
                    ,adSetUserPass
                    ,childrenOf, childrenOf'
                    ,fetchAllTypes
                    ,fromLdif, toLdif, fromLdifBS, toLdifBS
                    ,modOpsToLdif
                    ,rdnOf
                    ,recordOf
                    ,cmp
                    ,newRec, modRec, delRec, movRec
                    ,path2dn
                    ,nodeAttr
--                    ,recToTR, trToRec
--                    ,encode, decode
                    ,toJson, toJsonPP, fromJson
                    ) where

import Data.Aeson
import Data.Aeson.Encode.Pretty
import ADLDAP.Types
import ADLDAP.Parsers
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteString.Base64 as B64
import qualified Data.Map as M
import qualified Data.Set as S
import Data.Binary.Get
import LDAP.Search
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.List as L
import Data.Maybe (fromJust)
import qualified Data.Text as T
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ASN1.Encoding as Asn
import qualified Data.ASN1.BinaryEncoding as Asn
import qualified Data.ASN1.Types as Asn
import qualified Data.Map as M
import Data.Bits
import Control.Monad (replicateM)
import GHC.Word
import LDAP
import ADLDAP.LDIF.Parser (parseLdif)
import Debug.Trace
import Data.Maybe (isJust, fromJust)

adSetUserPass :: ADCtx -> DN -> Text -> IO ()
adSetUserPass ad dn' pass = ldapModify (ldap ad) (T.unpack . unTagged $ dn') [LDAPMod LdapModReplace "unicodePwd" [encodedPass]]
  where quotedPass = "\"" `T.append` pass `T.append` "\""
        encodedPass = (BC.unpack . T.encodeUtf16LE) quotedPass

modOpsToLdif :: ADCtx -> [ModOp] -> LdifMod
modOpsToLdif ad mops = undefined

fromLdifBS :: ADCtx -> ByteString -> [Record]
fromLdifBS ad bs = let ldif = Tagged . T.decodeUtf8 $ bs in fromLdif ad ldif

fromLdif :: ADCtx -> LdifRecs -> [Record]
fromLdif ad text = parseLdif (fromJust . lookupFunc) text
  where types = tmap ad
        lookupFunc = flip M.lookup types

toLdif :: [Record] -> LdifRecs
toLdif recs = Tagged $ T.unlines $ map (unTagged . recToLdif) recs

toLdifBS :: [Record] -> ByteString
toLdifBS = T.encodeUtf8 . unTagged . toLdif

recToLdif :: Record -> LdifRecs
recToLdif (Record dn attrs) = Tagged $ T.unlines $ ["dn: " <> unTagged dn] <> attrsToLdif attrs

attrsToLdif :: Attrs -> [Text]
attrsToLdif attrs = concatMap (\(k, (Attr t vals)) -> map (valToLdif k t) (S.toList vals)) $ M.toList attrs

valToLdif :: Key -> ADType -> Val -> Text
valToLdif k t v = unTagged k <> valToText k t v <> "\n# " <> T.pack (show t)

valToText :: Key -> ADType -> Val -> Text
valToText _ Boolean                   v = ": " <> T.decodeUtf8 v
valToText _ Integer                   v = ": " <> T.decodeUtf8 v
valToText _ Enumeration               v = ": " <> T.decodeUtf8 v
valToText _ LargeInteger              v = ": " <> T.decodeUtf8 v
valToText _ ObjectAccessPoint         v = ": " <> T.decodeUtf8 v
valToText _ ObjectDNString            v = ": " <> T.decodeUtf8 v
valToText _ ObjectORName              v = ": " <> T.decodeUtf8 v
valToText _ ObjectDNBinary            v = ": " <> T.decodeUtf8 v
valToText _ ObjectDSDN                v = ": " <> T.decodeUtf8 v
valToText _ ObjectPresentationAddress v = ": " <> T.decodeUtf8 v
valToText _ ObjectReplicaLink         v = ": " <> T.decodeUtf8 v
valToText _ StringCase                v = ": " <> T.decodeUtf8 v
valToText _ StringIA5                 v = ": " <> T.decodeUtf8 v
valToText _ StringNTSecDesc           v = ": " <> T.decodeUtf8 v
valToText _ StringNumeric             v = ": " <> T.decodeUtf8 v
valToText _ StringObjectIdentifier    v = ": " <> T.decodeUtf8 v
valToText "objectGUID" StringOctet    v = ":: " <> (T.decodeUtf8 $ B64.encode v) <> "\n# " <> T.pack (show $ parseGUID $ BL.fromStrict v)
valToText _ StringOctet               v = ":: " <> (T.decodeUtf8 $ B64.encode v)
valToText _ StringPrintable           v = ": " <> T.decodeUtf8 v
valToText _ StringSid                 v = ":: " <> (T.decodeUtf8 $ B64.encode v) <> "\n# " <> T.pack (show $ parseSID $ BL.fromStrict v)
valToText _ StringTeletex             v = ": " <> T.decodeUtf8 v
valToText _ StringUnicode             v = ": " <> T.decodeUtf8 v
valToText _ StringUTCTime             v = ": " <> T.decodeUtf8 v
valToText _ StringGeneralizedTime     v = ": " <> T.decodeUtf8 v
valToText _ (LinkedDN _)              v = ": " <> T.decodeUtf8 v


v2t :: Key -> ADType -> Val -> Text
v2t "objectGUID" StringOctet v = T.pack (show $ parseGUID $ BL.fromStrict v)
v2t _ StringSid v = T.pack (show $ parseSID $ BL.fromStrict v)
v2t _ StringOctet v = T.decodeUtf8 $ B64.encode v
v2t _ _ v = T.decodeUtf8 v

t2v :: Key -> ADType -> Text -> Val
t2v "objectGUID" StringOctet v = T.encodeUtf8 v
t2v _ StringSid v = T.encodeUtf8 v
t2v _ StringOctet v = B64.decodeLenient $ T.encodeUtf8 v
t2v _ _ v = T.encodeUtf8 v

allAttrs = ["*", "+"]

nodeAttr :: ADCtx -> DN -> Text -> IO [Val]
nodeAttr ad dn' attr = do
  (Record _ res) <- head <$> adSearch ad dn' Base Nothing [key]
  let (Attr _ vs) = fromJust $ M.lookup key res
  return $ S.toList vs
  where key = Tagged attr

recordOf :: ADCtx -> FilePath -> IO Record
recordOf ad path = head <$> adSearch ad (path2dn ad path) Base Nothing allAttrs
{--
childrenOf :: ADCtx -> FilePath -> IO [Record]
childrenOf ad path = adSearch ad (path2dn ad path) One Nothing [Tagged "*"]
--}
childrenOf :: ADCtx -> FilePath -> IO [Text]
childrenOf ad path = headOfDN <$> adSearch ad (path2dn ad path) One Nothing []
  where headOfDN = map (head . T.splitOn "," . unTag . dn)

childrenOf' :: ADCtx -> FilePath -> IO [Record]
childrenOf' ad path = adSearch ad (path2dn ad path) One Nothing allAttrs

rdnOf :: Record -> Text
rdnOf = head . T.splitOn "," . unTagged . dn

adSearchReq :: ADCtx -> DN -> Text -> IO [Record]
adSearchReq ad dn req = adSearch ad dn Sub filter attrs
  where (filter,attrs) = parseSearchRequest req

adSearch :: ADCtx -> DN -> Scope -> Maybe Filter -> [Key] -> IO [Record]
adSearch ad@ADCtx{..} dn scope filter attrs = do
  res <- ldapSearch ldap dn' scope' filter' attrs' False
  return $ map (le2r ad) res
  where dn' = Just $ T.unpack $ unTag dn
        scope' = lscope scope
        filter' = (T.unpack . unTag) <$> filter
        attrs' = lattrs attrs


addRealm :: ADCtx -> DN -> DN
addRealm ADCtx{..} dn | unTagged dn == "" = realm2dn adRealm
addRealm ADCtx{..} dn | otherwise =
  if T.isSuffixOf rdn dn' then dn else Tagged $ T.intercalate "," [dn', rdn]
  where rdn = unTagged realmDN
        dn' = unTagged dn
        realmDN = realm2dn adRealm

fromPath :: FilePath -> DN
fromPath = Tagged . T.intercalate "," . reverse . filter (/= "") . T.splitOn "/" . T.pack

path2dn :: ADCtx -> FilePath -> DN
path2dn ad path = addRealm ad $ fromPath path

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
  return $ M.fromList $ map (\(n, t) -> (Tagged (T.pack n), t)) $ (keys (findLinkPair res)) res
  where dn = "CN=Schema,CN=Configuration," <> dn'
        dn' = r2dnS adRealm
        attrs = LDAPAttrList ["lDAPDisplayName", "attributeSyntax", "oMSyntax", "oMObjectClass", "linkID"]
        keys flp = map (\(LDAPEntry _ vs) ->
                      let name = head $ fromJust $ L.lookup "lDAPDisplayName" vs
                          as = head $ fromJust $ L.lookup "attributeSyntax" vs
                          oms :: Int
                          oms = read $ head $ fromJust $ L.lookup "oMSyntax" vs
                          omo = case oms of
                                  127 -> oMObjectClassFromBER $ BC.pack $ head $ fromJust $ L.lookup "oMObjectClass" vs
                                  _ -> Nothing
                          res = (name, fromJust . fromOID $ (as, oms, omo))
                      in  case L.lookup "linkID" vs of
                            Nothing -> res
                            Just (lid:_) -> if odd (read lid) then (name, LinkedDN (flp (read lid))) else res
                   )
        t r = case oMObjectClassFromBER r of
                Just x -> x
                Nothing -> error $ "cannot decode " ++ (show r)

findLinkPair :: [LDAPEntry] -> Int -> Key
findLinkPair es lid = key
  where (LDAPEntry _ k) = head $ L.filter (\(LDAPEntry _ vs) -> let lid = L.lookup "linkID" vs in isJust lid && lid' == (head . fromJust $ lid)) es
        lid' = show $ lid - 1
        key = Tagged . T.pack . head . fromJust . L.lookup "lDAPDisplayName" $ k

oMObjectClassFromBER :: ByteString -> Maybe String
oMObjectClassFromBER hex = case Asn.decodeASN1' Asn.BER hex' of
  Right [Asn.OID x] -> Just $ stringify x
  Left _ -> Nothing
  where hex' = if 0x06 == B.head hex then hex else 0x06 `B.cons` (B.pack [len]) <> hex
        len = fromIntegral (B.length hex) :: Word8
        stringify = L.init . L.foldr (\a b -> show a <> "." <> b) ""

getAuthority :: Get Authority
getAuthority = do
  d <- getByteString 6
  let auth = sum $ map (\(n, b) -> fromIntegral (b `shiftR` n)) $ zip [0,8..] (reverse (B.unpack d))
  return $ Authority auth

getRID :: Get RID
getRID = do
  a <- getWord32le
  let rid = fromIntegral a
  return $ RID rid

parseSID' :: Get ObjectSID
parseSID' = do
  empty <- isEmpty
  if empty
    then return $ ObjectSID 0 0 (Authority 0) []
    else do r <- getWord8
            s <- getWord8
            a <- getAuthority
            rs <- replicateM (fromIntegral s) getRID
            return $ ObjectSID (fromIntegral r) (fromIntegral s) a rs

parseSID :: BL.ByteString -> ObjectSID
parseSID = runGet parseSID'

sid2str :: String -> String
sid2str s = show $ parseSID $ BL.pack s

parseGUID :: BL.ByteString -> ObjectGUID
parseGUID = runGet parseGUID'

parseGUID' :: Get ObjectGUID
parseGUID' = do
  empty <- isEmpty
  if empty
    then return $ ObjectGUID 0 0 0 0
    else ObjectGUID <$> getWord32le
                    <*> getWord16le
                    <*> getWord16le
                    <*> getWord64be

guid2str :: String -> String
guid2str s = show $ parseGUID $ BL.pack s

newRec :: ADCtx -> Record -> IO ()
newRec ad r = apply ad $ Add r

modRec :: ADCtx -> (DN, [AttrOp]) -> IO ()
modRec ad (dn, ops) = apply ad $ Mod dn ops

delRec :: ADCtx -> DN -> IO ()
delRec ad dn = apply ad $ Del dn

movRec :: ADCtx -> DN -> DN -> IO ()
movRec ad f t = apply ad $ Mov f t

apply :: ADCtx -> RecOp -> IO ()
apply ad (Add r)       = ldapAdd    (ldap ad) (T.unpack . unTagged . dn $ r) (recToLdapAdd r)
apply ad (Mod dn aops) = ldapModify (ldap ad) (T.unpack . unTagged $ dn) (concatMap aopToLdapMod aops)
apply ad (Del dn)      = ldapDelete (ldap ad) (T.unpack $ unTagged dn)
apply ad (Mov from to) = ldapRename (ldap ad) (T.unpack $ unTagged from) rdn prdn
  where rdn = T.unpack . head $ parts
        prdn = T.unpack . T.intercalate "," . tail $ parts
        parts = T.splitOn "," $ unTagged to

key2str :: Key -> String
key2str = T.unpack . unTagged

aopToLdapMod :: AttrOp -> [LDAPMod]
aopToLdapMod (AddAttr k vs) = [LDAPMod LdapModAdd (key2str k) (valsToStringList vs)]
aopToLdapMod (DeleteAttr k vs) = [LDAPMod LdapModDelete (key2str k) (valsToStringList vs)]
aopToLdapMod (ReplaceAttr k vs) = [LDAPMod LdapModReplace (key2str k) (valsToStringList vs)]
aopToLdapMod (ModifyAttr k vops) = map (vopToLdapMod k) vops

vopToLdapMod :: Key -> ValOp -> LDAPMod
vopToLdapMod k (AddVals vs) = LDAPMod LdapModAdd (key2str k) $ valsToStringList $ S.fromList vs
vopToLdapMod k (DelVals vs) = LDAPMod LdapModDelete (key2str k) $ valsToStringList $ S.fromList vs

valsToStringList :: Vals -> [String]
valsToStringList vs = map BC.unpack $ S.toList vs

recToLdapAdd :: Record -> [LDAPMod]
recToLdapAdd (Record dn attrs) = map (\(k, (Attr _ vs)) -> let k' = T.unpack (unTagged k) in LDAPMod LdapModAdd k' (valsToStringList vs)) $ M.toList filtered
  where filtered = M.filterWithKey (\k _ -> k `notElem` restrictedKeys) attrs

cmpVals :: Vals -> Vals -> (ValOp, ValOp)
cmpVals old new = (added, deleted)
  where added = AddVals $ S.toList $ S.difference new old
        deleted = DelVals $ S.toList $ S.difference old new

cmp :: Record -> Record -> (DN, [AttrOp])
cmp (Record oldDn oldAttrs) (Record newDn newAttrs) =
  let mm = M.intersection oldAttrs newAttrs
      addAttrs = map (\(k, as) -> AddAttr k (vals as))    $ M.toList $ M.difference newAttrs oldAttrs
      delAttrs = map (\(k, as) -> DeleteAttr k $ vals as) $ M.toList $ M.difference oldAttrs newAttrs
      modAttrs = map (\(k, op) -> op) $ M.toList $ M.mapMaybe id $ M.intersectionWithKey (
        \k (Attr ta as) (Attr tb bs) -> let newRecSize = S.size bs
                                            opsCount = length (vs adds) + length (vs dels)
                                            (adds, dels) = cmpVals as bs
                                        in if opsCount == 0 then Nothing
                                           else Just $ case opsCount `compare` newRecSize of
                                                         LT -> ModifyAttr k $ normOps [adds, dels]
                                                         _ -> ReplaceAttr k bs
        ) oldAttrs newAttrs
  in (oldDn, addAttrs <> delAttrs <> modAttrs)

normOps :: [ValOp] -> [ValOp]
normOps = filter (not . isEmpty)
  where isEmpty :: ValOp -> Bool
        isEmpty x = vs x == []

restrictedKeys :: [Key]
restrictedKeys =
  ["primaryGroupId"
  ,"cn"
  ,"distinguishedName"
  ,"memberOf"
  ,"name"
  ,"objectGUID"
  ,"objectSid"
  ,"primaryGroupID"
  ,"pwdLastSet" -- or MUST be 0 or -1
  ,"sAMAccountType"
  ,"uSNChanged"
  ,"uSNCreated"
  ,"whenChanged"
  ,"whenCreated"
  ,"isCriticalSystemObject"
  ]

recToTR :: Record -> TextRecord
recToTR (Record dn' attrs) = TextRecord (unTagged dn') vals
  where vals = M.fromList $ map (\(k, (Attr t vs)) -> (unTagged k, (t, S.map (v2t k t) vs))) as
        as = M.toList attrs

trToRec :: TextRecord -> Record
trToRec trec = Record dn' attrs
  where dn' = Tagged $ trDN trec
        attrs = M.fromList $ map (\(k, (t, vs)) -> (Tagged k, Attr t (S.map (t2v (Tagged k) t) vs))) as
        as = M.toList $ trAttrs trec

toJson :: Record -> Text
toJson = T.decodeUtf8 . BL.toStrict . encode . recToTR

toJsonPP :: Record -> Text
toJsonPP = T.decodeUtf8 . BL.toStrict . encodePretty . recToTR

fromJson :: Text -> Record
fromJson t = trToRec recs
  where recs = case decode . BL.fromStrict . T.encodeUtf8 $ t of
                 Nothing -> error $ "cannot decode as a TextRecord: " ++ (T.unpack t)
                 Just x -> x

