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
  , readStandardFulfillment
  ) where

import qualified Crypto.PubKey.Ed25519 as Ed2

import Data.ByteString as BS
import Data.Word
import qualified Data.Set as Set

import Network.CryptoConditions.Impl as CCI


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

  getFulfillment (Threshold t subs) = thresholdFulfillment t subs
  getFulfillment (Ed25519 pk msig) = ed25519Fulfillment pk <$> msig
  getFulfillment (Preimage pre) = Just $ preimageFulfillment pre
  getFulfillment (Prefix pre mml c) =  prefixFulfillment pre mml c
  getFulfillment (Anon _ _ _ _) = Nothing

  getSubtypes (Threshold _ sts) = thresholdSubtypes sts
  getSubtypes (Anon _ _ _ sts) = sts
  getSubtypes (Prefix _ _ c)     = prefixSubtypes c
  getSubtypes _                = mempty

  parseFulfillment 0 = parsePreimage Preimage
  parseFulfillment 1 = parsePrefix Prefix
  parseFulfillment 2 = parseThreshold Threshold
  parseFulfillment 4 = parseEd25519 (\a b -> Ed25519 a (Just b))

  anon t f c = Anon t f c . toConditionTypes


toConditionTypes :: Set.Set Int -> Set.Set ConditionType
toConditionTypes = Set.map $
  let u = undefined in (\tid -> getType $ Anon tid u u u)


preimageCondition :: BS.ByteString -> Condition
preimageCondition = Preimage


ed25519Condition :: Ed2.PublicKey -> Condition
ed25519Condition pk = Ed25519 pk Nothing


fulfillEd25519 :: Ed2.PublicKey -> Ed2.Signature
               -> Condition -> Condition
fulfillEd25519 pk sig (Threshold t subs) =
  Threshold t $ fulfillEd25519 pk sig <$> subs
fulfillEd25519 pk sig e@(Ed25519 pk' Nothing) =
  if pk == pk' then Ed25519 pk (Just sig) else e
fulfillEd25519 _ _ c = c


readStandardFulfillment :: Message -> Fulfillment -> Either String Condition
readStandardFulfillment = readFulfillment
