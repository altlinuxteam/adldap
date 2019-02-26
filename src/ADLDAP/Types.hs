{-# LANGUAGE
DeriveGeneric,
FlexibleInstances
#-}
module ADLDAP.Types where

import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.Map (Map)
import Data.Set (Set)
import qualified Data.Set as S
import qualified Data.Map as M
import LDAP
import Data.Binary
import GHC.Generics
import qualified Data.ByteString.Base64 as B64

data ADCtx = ADCtx{adRealm :: !Realm
                  ,adHost  :: !Host
                  ,adPort  :: !Port
                  ,ldap    :: !LDAP
                  ,tmap    :: !TypeMap
                  }
  deriving (Eq,Show)

type Realm = Text
type Host = String
type Port = Int

data DnTag
data KeyTag

newtype Tagged tag a = Tagged {unTagged :: a} deriving (Eq, Ord)
unTag = unTagged
instance Show a => Show (Tagged tag a) where
  show = show . unTagged

type DN = Tagged DnTag Text  
type Key = Tagged KeyTag Text
type Val = ByteString
data Attr = Attr !ADType !(Set Val)
instance Semigroup Attr where
  (Attr t a) <> (Attr _ b) = Attr t (a <> b)
instance Eq Attr where
  (==) (Attr _ a) (Attr _ b) = a == b

type Attrs = Map Key Attr

mkAttrs :: [(Key, Attr)] -> Attrs
mkAttrs = foldl (flip $ uncurry $ M.insertWith (<>)) M.empty

mkVal :: [Val] -> Set Val
mkVal = S.fromList


instance Show Attr where
  show (Attr t vs) = unlines $ map (showVal t) $ S.toList vs

showVal :: ADType -> Val -> String
showVal StringUnicode v = BC.unpack v
showVal _ v = BC.unpack $ B64.encode v

data Record = Record{dn    :: !DN
                    ,attrs :: !Attrs
                    }
  deriving (Eq, Show)

data RecOp = AddRec Record
           | DeleteRec DN
           | MoveRec DN DN
  deriving (Eq, Show)

data AttrOp = AddVals Record
            | DeleteVals Record
            | ReplaceVals Record
  deriving (Eq, Show)

data ModOp = ModOp {recOps :: [RecOp], attrOps :: [AttrOp]} deriving (Eq, Show)

data LdifRecsTag
data LdifModTag
type LdifRecs = Tagged LdifRecsTag Text
type LdifMod = Tagged LdifModTag Text

type TypeMap = Map Key ADType
type TypeResolver = (Key -> ADType)

class OID a where
  fromOID :: (String,Int,Maybe String) -> Maybe a
  toOID :: a -> Maybe (String,Int,Maybe String)

data ADType = Boolean
            | Integer
            | Enumeration
            | LargeInteger
            | ObjectAccessPoint
            | ObjectDNString
            | ObjectORName
            | ObjectDNBinary
            | ObjectDSDN
            | ObjectPresentationAddress
            | ObjectReplicaLink
            | StringCase
            | StringIA5
            | StringNTSecDesc
            | StringNumeric
            | StringObjectIdentifier
            | StringOctet
            | StringPrintable
            | StringSid
            | StringTeletex
            | StringUnicode
            | StringUTCTime
            | StringGeneralizedTime
  deriving (Eq, Ord, Show, Generic)
instance Binary ADType

instance OID ADType where
  fromOID ("2.5.5.8",    1, Nothing)                        = Just Boolean
  fromOID ("2.5.5.9",   10, Nothing)                        = Just Enumeration
  fromOID ("2.5.5.9",    2, Nothing)                        = Just Integer
  fromOID ("2.5.5.16",  65, Nothing)                        = Just LargeInteger
  fromOID ("2.5.5.14", 127, Just "1.3.12.2.1011.28.0.702")  = Just ObjectAccessPoint
  fromOID ("2.5.5.14", 127, Just "1.2.840.113556.1.1.1.12") = Just ObjectDNString
  fromOID ("2.5.5.7",  127, Just "2.6.6.1.2.5.11.29")       = Just ObjectORName
  fromOID ("2.5.5.7",  127, Just "1.2.840.113556.1.1.1.11") = Just ObjectDNBinary
  fromOID ("2.5.5.1",  127, Just "1.3.12.2.1011.28.0.714")  = Just ObjectDSDN
  fromOID ("2.5.5.13", 127, Just "1.3.12.2.1011.28.0.732")  = Just ObjectPresentationAddress
  fromOID ("2.5.5.10", 127, Just "1.2.840.113556.1.1.1.6")  = Just ObjectReplicaLink
  fromOID ("2.5.5.3",   27, Nothing)                        = Just StringCase
  fromOID ("2.5.5.5",   22, Nothing)                        = Just StringIA5
  fromOID ("2.5.5.15",  66, Nothing)                        = Just StringNTSecDesc
  fromOID ("2.5.5.6",   18, Nothing)                        = Just StringNumeric
  fromOID ("2.5.5.2",    6, Nothing)                        = Just StringObjectIdentifier
  fromOID ("2.5.5.10",   4, Nothing)                        = Just StringOctet
  fromOID ("2.5.5.5",   19, Nothing)                        = Just StringPrintable
  fromOID ("2.5.5.17",   4, Nothing)                        = Just StringSid
  fromOID ("2.5.5.4",   20, Nothing)                        = Just StringTeletex
  fromOID ("2.5.5.12",  64, Nothing)                        = Just StringUnicode
  fromOID ("2.5.5.11",  23, Nothing)                        = Just StringUTCTime
  fromOID ("2.5.5.11",  24, Nothing)                        = Just StringGeneralizedTime
  fromOID _ = Nothing

  toOID Boolean                   = Just ("2.5.5.8",    1, Nothing)
  toOID Enumeration               = Just ("2.5.5.9",   10, Nothing)
  toOID Integer                   = Just ("2.5.5.9",    2, Nothing)
  toOID LargeInteger              = Just ("2.5.5.16",  65, Nothing)
  toOID ObjectAccessPoint         = Just ("2.5.5.14", 127, Just "1.3.12.2.1011.28.0.702")
  toOID ObjectDNString            = Just ("2.5.5.14", 127, Just "1.2.840.113556.1.1.1.12")
  toOID ObjectORName              = Just ("2.5.5.7",  127, Just "2.6.6.1.2.5.11.29")
  toOID ObjectDNBinary            = Just ("2.5.5.7",  127, Just "1.2.840.113556.1.1.1.11")
  toOID ObjectDSDN                = Just ("2.5.5.1",  127, Just "1.3.12.2.1011.28.0.714")
  toOID ObjectPresentationAddress = Just ("2.5.5.13", 127, Just "1.3.12.2.1011.28.0.732")
  toOID ObjectReplicaLink         = Just ("2.5.5.10", 127, Just "1.2.840.113556.1.1.1.6")
  toOID StringCase                = Just ("2.5.5.3",   27, Nothing)
  toOID StringIA5                 = Just ("2.5.5.5",   22, Nothing)
  toOID StringNTSecDesc           = Just ("2.5.5.15",  66, Nothing)
  toOID StringNumeric             = Just ("2.5.5.6",   18, Nothing)
  toOID StringObjectIdentifier    = Just ("2.5.5.2",    6, Nothing)
  toOID StringOctet               = Just ("2.5.5.10",   4, Nothing)
  toOID StringPrintable           = Just ("2.5.5.5",   19, Nothing)
  toOID StringSid                 = Just ("2.5.5.17",   4, Nothing)
  toOID StringTeletex             = Just ("2.5.5.4",   20, Nothing)
  toOID StringUnicode             = Just ("2.5.5.12",  64, Nothing)
  toOID StringUTCTime             = Just ("2.5.5.11",  23, Nothing)
  toOID StringGeneralizedTime     = Just ("2.5.5.11",  24, Nothing)

data FilterTag
type Filter = Tagged FilterTag Text

data Scope = Base
           | One
           | Sub
  deriving (Eq, Show)
