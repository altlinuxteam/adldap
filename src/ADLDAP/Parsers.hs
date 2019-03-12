module ADLDAP.Parsers where
import ADLDAP.Types
import Data.Text (Text)
import qualified Data.Text as T
import Data.Attoparsec.Text
import Data.Attoparsec.Combinator

parseSearchRequest :: Text -> (Maybe Filter, [Key])
parseSearchRequest req = case parseOnly sreqP req of
  Left e -> error $ "cannot parse " ++ e
  Right res -> res

sreqP :: Parser (Maybe Filter, [Key])
sreqP = do
  skipSpace
  filter <- option Nothing (Just <$> filterP)
  skipSpace
  attrs <- attrsP
  return (filter,attrs)

filterP :: Parser Filter
filterP = do
  attrs <- string "(" *> manyTill anyChar (string ") ")
  return $ Tagged $ T.pack $ "(" ++ attrs ++ ")"

attrsP :: Parser [Key]
attrsP = do
  attrs <- takeText
  return $ map Tagged $ T.words attrs
