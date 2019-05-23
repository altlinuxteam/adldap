{-# LANGUAGE CPP #-}
module ADLDAP.LDIF.Parser where

import Data.Attoparsec.Text
import Data.Attoparsec.Combinator
import qualified Data.ByteString.Base64 as B64
import Data.Text (Text, cons)
import Data.Text.Encoding
import ADLDAP.Types
import Prelude ()
import Prelude.Compat
#if MIN_VERSION_base(4,6,0)
import Control.Applicative
import Data.Semigroup ((<>))
#endif

parseLdif :: TypeResolver -> LdifRecs -> [Record]
parseLdif keyToType text = case parseOnly (ldifP keyToType) (unTagged text) of
  Left e -> error $ "cannot parse: " ++ e
  Right rs -> rs

ldifP :: TypeResolver -> Parser [Record]
ldifP keyToType = do
  skipTrash
  many1 (recP keyToType)

recP :: TypeResolver -> Parser Record
recP keyToType = do
  many' comment
  dn <- dnP
  many' comment
  attrs <- many' (attrP keyToType)
  many' comment
  choice [endOfLine, endOfInput]
  return $ Record dn (mkAttrs attrs)

dnP :: Parser DN
dnP = do
  string "dn: "
  skipSpace
  dn <- takeTill isEndOfLine
  many' comment
  endOfLine
  return $ Tagged dn

attrP :: TypeResolver -> Parser (Key, Attr)
attrP keyToType = do
  many' comment
  key <- keyP
  many' comment
  val <- valP
  many' comment
  choice [endOfLine, endOfInput]
  return $ (key, Attr (keyToType key) (mkVal [val]))

keyP :: Parser Key
keyP = do
  first <- letter
  rest <- takeTill (':'==)
  return $ Tagged $ cons first rest

valP :: Parser Val
valP = choice [textVal, base64Val]

textVal :: Parser Val
textVal = do
  string ": "
  encodeUtf8 <$> val'

base64Val :: Parser Val
base64Val = do
  string ":: "
  B64.decodeLenient . encodeUtf8 <$> val'

val' :: Parser Text
val' = do
  v <- takeTill isEndOfLine
  rs <- option "" rest
  return (v <> rs)
  where rest :: Parser Text
        rest = do
          string "\n "
          skipWhile (==' ')
          takeTill isEndOfLine

skipTrash :: Parser ()
skipTrash = do
  many' $ choice [endOfLine, comment]
  return ()

comment :: Parser ()
comment = char '#' >> skipWhile (not . isEndOfLine) >> endOfLine
