{-# LANGUAGE OverloadedStrings #-}

module Network.CryptoConditions.Json
  ( parseJsonPreimage
  , parseJsonPrefix
  , parseJsonThreshold
  , parseJsonEd25519
  , toJsonPreimage
  , toJsonPrefix
  , toJsonThreshold
  , toJsonEd25519
  ) where


import Crypto.PubKey.Ed25519
import Crypto.Error

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import Data.ByteString as BS
import Data.Text
import Data.Text.Encoding
import Data.Word

import Network.CryptoConditions.Encoding
import Network.CryptoConditions.Impl


-- Parsing
--

parseJsonThreshold :: (IsCondition c, FromJSON c) => (Word16 -> [c] -> c) -> Object -> Parser c
parseJsonThreshold f obj = f <$> obj .: "threshold" <*> obj .: "subfulfillments"


parseJsonEd25519 :: IsCondition c => (PublicKey -> Maybe Signature -> c) -> Object -> Parser c
parseJsonEd25519 f obj = do
  pub <- obj .: "publicKey" >>= parseKey publicKey
  msig <- obj .:? "signature" >>= mapM (parseKey signature)
  pure $ f pub msig


parseJsonPrefix :: (IsCondition c, FromJSON c) => (ByteString -> Int -> c -> c) -> Object -> Parser c
parseJsonPrefix f obj = do
  pre <- obj .: "prefix" >>= fromB64
  f pre <$> obj .: "maxMessageLength" <*> obj .: "subfulfillment"


parseJsonPreimage :: IsCondition c => (ByteString -> c) -> Object -> Parser c
parseJsonPreimage f obj =
  f <$> (obj .: "preimage" >>= fromB64)


-- Encoding
--

toJsonPreimage :: ByteString -> Value
toJsonPreimage img = object ["type" .= String "preimage-sha-256", "preimage" .= binToJson img]


toJsonPrefix :: (IsCondition c, ToJSON c) => ByteString -> Int -> c -> Value
toJsonPrefix pre mml sub =
  object [ "type".= String "prefix-sha-256"
         , "prefix" .= binToJson pre
         , "subfulfillment" .= sub
         ]


toJsonThreshold :: (IsCondition c, ToJSON c) => Word16 -> [c] -> Value
toJsonThreshold threshold subs =
  object [ "type" .= String "threshold-sha-256"
         , "threshold" .= threshold
         , "subfulfillments" .= subs
         ]


toJsonEd25519 :: PublicKey -> Maybe Signature -> Value
toJsonEd25519 pk msig =
  let sigItem = maybe [] (\sig -> ["signature" .= keyToJson sig]) msig
   in object $ ["type" .= String "ed25519-sha-256", "publicKey" .= keyToJson pk] ++ sigItem


-- Util
--

fromB64 :: Text -> Parser ByteString
fromB64 = either fail pure . b64DecodeStripped . encodeUtf8


parseKey :: (ByteString -> CryptoFailable b) -> Text -> Parser b
parseKey f bs = do
  bin <- either fail pure $ b64DecodeStripped $ encodeUtf8 bs
  onCryptoFailure (fail . show) pure $ f bin


keyToJson :: BA.ByteArrayAccess k => k -> Value
keyToJson = String . decodeUtf8 . b64EncodeStripped . BS.pack . BA.unpack


binToJson :: ByteString -> Value
binToJson = String . decodeUtf8 . b64EncodeStripped
