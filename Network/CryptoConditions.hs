{-# LANGUAGE OverloadedStrings #-}

--------------------------------------------------------------------------------
-- Crypto Conditions Standard API
--
-- The Condition type defined in this module supports the standard
-- condition types, library authors wishing to extend CryptoConditions
-- should copy and paste this file into their own project and define their own
-- Condition type.
--------------------------------------------------------------------------------

module Network.CryptoConditions
  ( module CCI
  , Condition(..)
  , ed25519Condition
  , preimageCondition
  , fulfillEd25519
  ) where

import qualified Crypto.PubKey.Ed25519 as Ed2

import Data.Aeson.Types
import Data.ByteString as BS
import Data.Monoid
import Data.Word
import qualified Data.Set as Set

import Network.CryptoConditions.Impl as CCI
import Network.CryptoConditions.Json as CCJ


data Condition =
    Preimage Preimage
  | Prefix Prefix Int Condition
  | Threshold Word16 [Condition]
--  Rsa
  | Ed25519 Ed2.PublicKey (Maybe Ed2.Signature)
  | Anon Int Fingerprint Int (Set.Set ConditionType)
  deriving (Show, Eq)


instance IsCondition Condition where
  getType (Anon 0 _ _ _) = preimageType
  getType (Anon 1 _ _ _) = prefixType
  getType (Anon 2 _ _ _) = thresholdType
  getType (Anon 4 _ _ _) = ed25519Type
  getType (Threshold _ _) = thresholdType
  getType (Ed25519 _ _) = ed25519Type
  getType (Preimage _) = preimageType
  getType (Prefix _ _ _) = prefixType

  getCost (Threshold t subs) = thresholdCost t subs
  getCost (Ed25519 _ _) = ed25519Cost
  getCost (Preimage pre) = preimageCost pre
  getCost (Prefix pre mml c) = prefixCost pre mml c
  getCost (Anon _ _ c _) = c

  getFingerprint (Threshold t subs) = thresholdFingerprint t subs
  getFingerprint (Ed25519 pk _) = ed25519Fingerprint pk
  getFingerprint (Preimage pre) = preimageFingerprint pre
  getFingerprint (Prefix pre mml c) = prefixFingerprint pre mml c
  getFingerprint (Anon _ fp _ _) = fp

  getFulfillmentASN (Threshold t subs) = thresholdFulfillmentASN t subs
  getFulfillmentASN (Ed25519 pk msig) = ed25519FulfillmentASN pk <$> msig
  getFulfillmentASN (Preimage pre) = Just $ preimageFulfillmentASN pre
  getFulfillmentASN (Prefix pre mml c) =  prefixFulfillmentASN pre mml c
  getFulfillmentASN (Anon _ _ _ _) = Nothing

  getSubtypes (Threshold _ sts) = thresholdSubtypes sts
  getSubtypes (Anon _ _ _ sts) = sts
  getSubtypes (Prefix _ _ c)     = prefixSubtypes c
  getSubtypes _                = mempty

  parseFulfillment 0 = parsePreimage Preimage
  parseFulfillment 1 = parsePrefix Prefix
  parseFulfillment 2 = parseThreshold Threshold
  parseFulfillment 4 = parseEd25519 (\a b -> Ed25519 a (Just b))

  verifyMessage (Preimage image) = verifyPreimage image
  verifyMessage (Prefix pre mml cond) = verifyPrefix pre mml cond
  verifyMessage (Threshold m subs) = verifyThreshold m subs
  verifyMessage (Ed25519 pk (Just sig)) = verifyEd25519 pk sig
  verifyMessage _ = const False

  anon t f c = Anon t f c . toConditionTypes


toConditionTypes :: Set.Set Int -> Set.Set ConditionType
toConditionTypes = Set.map $
  let u = undefined in (\tid -> getType $ Anon tid u u u)


preimageCondition :: BS.ByteString -> Condition
preimageCondition = Preimage


ed25519Condition :: Ed2.PublicKey -> Condition
ed25519Condition pk = Ed25519 pk Nothing


fulfillEd25519 :: Ed2.PublicKey -> Ed2.SecretKey
               -> Message -> Condition -> Condition
fulfillEd25519 pk sk msg c@(Ed25519 pk' _) =
  if pk == pk' then Ed25519 pk (Just $ Ed2.sign sk pk msg) else c
fulfillEd25519 pk sk msg (Threshold t subs) =
  Threshold t $ fulfillEd25519 pk sk msg <$> subs
fulfillEd25519 pk sk msg (Prefix pre mml sub) =
  Prefix pre mml $ fulfillEd25519 pk sk (pre <> msg) sub
fulfillEd25519 _ _ _ c = c


instance ToJSON Condition where
  toJSON (Threshold t subs) = toJsonThreshold t subs
  toJSON (Ed25519 pk msig) = toJsonEd25519 pk msig
  toJSON (Prefix pre mml c) = toJsonPrefix pre mml c
  toJSON (Preimage img) = toJsonPreimage img


instance FromJSON Condition where
  parseJSON = withObject "condition" $ \o -> do
    typeName <- o .: "type"
    let method = case typeName of
         "preimage-sha-256" -> CCJ.parseJsonPreimage Preimage
         "prefix-sha-256" -> parseJsonPrefix Prefix
         "threshold-sha-256" -> parseJsonThreshold Threshold
         "ed25519-sha-256" -> parseJsonEd25519 Ed25519
         _                 -> fail ("Unknown Crypto-Condition type: " ++ typeName)
    method o
