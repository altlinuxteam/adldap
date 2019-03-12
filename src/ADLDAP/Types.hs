{-# LANGUAGE
DeriveGeneric,
FlexibleInstances
#-}
module ADLDAP.Types where

import Data.Aeson
import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.Map (Map)
import Data.Set (Set)
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.String (IsString(..))
import qualified Data.Map as M
import LDAP
import Numeric (showHex)
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

newtype Tagged tag a = Tagged {unTagged :: a} deriving (Eq, Ord, Generic)

unTag = unTagged
instance Show a => Show (Tagged tag a) where
  show = show . unTagged

type DN = Tagged DnTag Text
instance IsString DN where
  fromString = Tagged . T.pack

type Key = Tagged KeyTag Text
instance IsString Key where
  fromString = Tagged . T.pack
instance ToJSON (Tagged KeyTag Text)
instance FromJSON (Tagged KeyTag Text)

type Val = ByteString
type Vals = Set Val
data Attr = Attr !ADType !Vals deriving Generic
instance Semigroup Attr where
  (Attr t a) <> (Attr _ b) = Attr t (a <> b)
instance Eq Attr where
  (==) (Attr _ a) (Attr _ b) = a == b
instance Show Attr where
  show (Attr t a) = show t ++ show a

type Attrs = Map Key Attr

vals :: Attr -> Vals
vals (Attr _ vs) = vs

mkAttrs :: [(Key, Attr)] -> Attrs
mkAttrs = foldl (flip $ uncurry $ M.insertWith (<>)) M.empty

mkVal :: [Val] -> Set Val
mkVal = S.fromList

data Record = Record{dn    :: !DN
                    ,attrs :: !Attrs
                    }
  deriving (Eq, Show, Generic)

data TextRecord = TextRecord{trDN :: !Text
                            ,trAttrs :: Map Text (ADType, Set Text)
                            }
  deriving (Eq, Show, Generic)
instance FromJSON TextRecord
instance ToJSON TextRecord

data RecOp = Add !Record
           | Mod !DN ![AttrOp]
           | Del !DN
           | Mov !DN !DN
  deriving (Eq, Show)

data AttrOp = AddAttr Key Vals
            | DeleteAttr Key Vals
            | ReplaceAttr Key Vals
            | ModifyAttr Key [ValOp]
  deriving (Eq, Show)

data ValOp = AddVals { vs :: ![Val]}
           | DelVals { vs :: ![Val]}
  deriving (Eq, Show)

data ModOp = ModOp {recOps :: [RecOp], attrOps :: [AttrOp]} deriving (Eq, Show)

data LdifRecsTag
data LdifModTag
type LdifRecs = Tagged LdifRecsTag Text
instance IsString LdifRecs where
  fromString = Tagged . T.pack

type LdifMod = Tagged LdifModTag Text
instance IsString LdifMod where
  fromString = Tagged . T.pack


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
            | LinkedDN Key
  deriving (Eq, Ord, Show, Generic)
instance ToJSON ADType
instance FromJSON ADType


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

newtype Authority = Authority Int deriving (Eq, Show)
newtype RID = RID Int deriving (Eq, Show)

data ObjectSID =
  ObjectSID{ rev :: Int
           , subAuthCount :: Int
           , auth :: Authority
           , rids :: [RID]
           }
  deriving (Eq)
instance Show ObjectSID where
  show (ObjectSID r _ (Authority a) rs) = "S-" ++ show r ++ "-" ++ show a ++ concatMap (\(RID x) -> "-" ++ show x) rs

data ObjectGUID =
  ObjectGUID{ f1 :: Word32
            , f2 :: Word16
            , f3 :: Word16
            , f4 :: Word64
            }
  deriving (Eq)
instance Show ObjectGUID where
  show (ObjectGUID f1' f2' f3' f4') = showHex f1' "-" ++ showHex f2' "-" ++ showHex f3' "-" ++ f4_1 ++ "-" ++ f4_2
    where f4_h = showHex f4' ""
          f4_1 = take 4 f4_h
          f4_2 = drop 4 f4_h
