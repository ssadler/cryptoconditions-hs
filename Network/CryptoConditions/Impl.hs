{-# LANGUAGE OverloadedStrings #-}


module Network.CryptoConditions.Impl where


import Crypto.Hash
import qualified Crypto.PubKey.Ed25519 as Ed2

import Control.Monad (when)

import Data.ASN1.BinaryEncoding
import Data.ASN1.BinaryEncoding.Raw
import Data.ASN1.Encoding
import Data.ASN1.Parse
import Data.ASN1.Types
import Data.Bits
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import Data.List (sortOn)
import Data.Maybe
import Data.Monoid
import qualified Data.Set as Set
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8)
import Data.Word

import Network.CryptoConditions.Encoding


--------------------------------------------------------------------------------
-- | Class of things that are conditions
--
class Show c => IsCondition c where
  getCost :: c -> Int
  getType :: c -> ConditionType
  getFingerprint :: c -> BS.ByteString
  getFulfillment :: c -> Maybe BS.ByteString
  getSubtypes :: c -> Set.Set ConditionType
  getURI :: c -> T.Text
  getURI = getConditionURI
  parseFulfillment :: Int -> Message -> ParseASN1 c
  anon :: Int -> BS.ByteString -> Int -> Set.Set Int -> c


-- Parameter aliases
type Message = BS.ByteString
type Fulfillment = BS.ByteString
type Preimage = BS.ByteString
type Prefix = BS.ByteString
type Fingerprint = BS.ByteString


encodeCondition :: IsCondition c => c -> BS.ByteString
encodeCondition = encodeASN1' DER . encodeConditionASN


encodeConditionASN :: IsCondition c => c -> [ASN1]
encodeConditionASN c =
  let ct = getType c
      fingerprint = getFingerprint c
      costBs = BS.pack $ bytesOfUInt $ fromIntegral $ getCost c
      subtypes = "\a" <> (typeMask $ Set.map typeId $ getSubtypes c)
      body = [fingerprint, costBs] ++
             if hasSubtypes ct then [subtypes] else []
   in fiveBellsContainer (typeId ct) body


getConditionURI :: IsCondition c => c -> T.Text
getConditionURI c =
  let ct = getType c
      f = decodeUtf8 $ b64EncodeStripped $ getFingerprint c
      cost = T.pack $ show $ getCost c
      subtypes = if hasSubtypes ct
                    then "&subtypes=" <> typeNames (getSubtypes c)
                    else ""
   in "ni:" <> hashFunc ct <> ";" <> f
       <> "?fpt=" <> typeName ct <> "&cost="
       <> cost <> subtypes


getFulfillmentBase64 :: IsCondition c => c -> Maybe T.Text
getFulfillmentBase64 =
  fmap (decodeUtf8 . B64.encode) . getFulfillment


readFulfillment :: IsCondition c => Message -> Fulfillment
                -> Either String c
readFulfillment msg bs = parseASN1 bs (verifyPoly msg)


verifyPoly :: IsCondition c => Message -> ParseASN1 c
verifyPoly msg = withContainerContext (flip parseFulfillment msg)


--------------------------------------------------------------------------------
-- | Type of a condition
--
data ConditionType = CT
  { typeId :: Int
  , typeName :: T.Text
  , hasSubtypes :: Bool
  , hashFunc :: T.Text
  }
  deriving (Show)


-- Eq and Ord instances consider only the ID
--
instance Eq ConditionType where
  ct == ct' = typeId ct == typeId ct'


instance Ord ConditionType where
  ct <= ct' = typeId ct <= typeId ct'


-- Functions for working with sets of condition types
--
typeNames :: Set.Set ConditionType -> T.Text
typeNames = T.intercalate "," . map typeName . Set.toAscList


-- This should figure prepend the range itself.
typeMask :: Set.Set Int -> BS.ByteString
typeMask cts =
  let op i = shiftL 1 (7 - mod i 8)
      bits = Set.map op cts
      mask = foldl (.|.) 0 bits :: Int
   in BS.singleton $ fromIntegral mask


unTypeMask :: BS.ByteString -> Set.Set Int
unTypeMask maskbs = Set.fromList $
  let [n, w] = fromIntegral <$> BS.unpack maskbs
   in filter (\i -> 0 /= w .&. (shiftL 1 (n-i))) [0..n]


--------------------------------------------------------------------------------
-- | (0) Preimage Condition
--

preimageType :: ConditionType
preimageType = CT 0 "preimage-sha-256" False "sha-256"


preimageFulfillment :: BS.ByteString -> Fulfillment
preimageFulfillment pre = encodeASN1' DER body
  where body = fiveBellsContainer (typeId preimageType) [pre]


preimageCost :: BS.ByteString -> Int
preimageCost = BS.length


preimageFingerprint :: Preimage -> Fingerprint
preimageFingerprint = sha256


parsePreimage :: (Preimage -> c) -> Message -> ParseASN1 c
parsePreimage construct _ = construct <$> parseOther 0


--------------------------------------------------------------------------------
-- | (1) Prefix condition


prefixType :: ConditionType
prefixType = CT 1 "prefix-sha-256" True "sha-256"


prefixCost :: IsCondition c => Prefix -> Int -> c -> Int
prefixCost pre maxMessageLength c =
  BS.length pre + getCost c + 1024 + maxMessageLength


prefixFingerprint :: IsCondition c => Prefix -> Int -> c -> Fingerprint
prefixFingerprint pre mml cond = sha256 body
  where body = encodeASN1' DER asn
        mmlbs = BS.pack $ bytesOfUInt $ fromIntegral mml
        condAsn = encodeConditionASN cond
        asn = asnSeq Sequence $
              [ Other Context 0 pre
              , Other Context 1 mmlbs
              ] ++ asnSeq (Container Context 2) condAsn


prefixFulfillment :: IsCondition c => Prefix -> Int -> c -> Maybe Fulfillment
prefixFulfillment pre mml cond =
  let mmlbs = BS.pack $ bytesOfUInt $ fromIntegral mml
      msubffill = getFulfillment cond
      getAsn subffill =
        let subAsn = either (error . show) id $ decodeASN1' DER $ subffill
         in asnSeq (Container Context 1) $
             [ Other Context 0 pre
             , Other Context 1 mmlbs
             ] ++ asnSeq (Container Context 2) subAsn
   in encodeASN1' DER . getAsn <$> msubffill


prefixSubtypes :: IsCondition c => c -> Set.Set ConditionType
prefixSubtypes cond =
  let cts = Set.singleton $ getType cond
      all' = Set.union cts $ getSubtypes cond
   in Set.delete prefixType all'


parsePrefix :: IsCondition c => (Prefix -> Int -> c -> c) -> Message
            -> ParseASN1 c
parsePrefix construct msg = do
  (pre, mmlbs) <- (,) <$> parseOther 0 <*> parseOther 1
  let mml = fromIntegral $ uIntFromBytes $ BS.unpack mmlbs
  when (mml < BS.length msg) $
    throwParseError "Max message length exceeded" -- TODO
  -- TODO: D is equal to C?
  cond <- onNextContainer (Container Context 2) (verifyPoly (pre <> msg))
  pure $ construct pre mml cond


--------------------------------------------------------------------------------
-- | (2) Threshold condition
--

thresholdType :: ConditionType
thresholdType = CT 2 "threshold-sha-256" True "sha-256"


thresholdFulfillment :: IsCondition c => Word16 -> [c] -> Maybe Fulfillment
thresholdFulfillment t subs =
  let ti = fromIntegral t
      withFf = zip subs (getFulfillment <$> subs)
      byCost = sortOn ffillCost withFf
      ffills = take ti $ catMaybes $ snd <$> byCost
      conds = encodeConditionASN . fst <$> drop ti byCost
      ffills' = either (error . show) id . decodeASN1' DER <$> ffills
      asn = asnSeq (Container Context 2) $
              asnSeq (Container Context 0) (concat ffills') ++
              asnSeq (Container Context 1) (concat conds)
      encoded = encodeASN1' DER asn
   in if length ffills == ti then Just encoded else Nothing
  where
    -- order by has ffill then cost of ffill
    ffillCost (c, Just _) = (0::Int, getCost c)
    ffillCost _           = (1, 0)


thresholdFingerprint :: IsCondition c => Word16 -> [c] -> Fingerprint
thresholdFingerprint t subs =
  let asns = encodeConditionASN <$> subs
   in thresholdFingerprintFromAsns t asns


thresholdFingerprintFromAsns :: Word16 -> [[ASN1]] -> Fingerprint
thresholdFingerprintFromAsns t asns = 
  let subs' = x690SortAsn asns -- TODO: encode only once?
      c = Container Context 1
      asn = asnSeq Sequence $
        [ Other Context 0 (BS.pack $ bytesOfUInt $ fromIntegral t)
        , Start c
        ] ++ concat subs' ++ [End c]
   in sha256 $ encodeASN1' DER asn


thresholdSubtypes :: IsCondition c => [c] -> Set.Set ConditionType
thresholdSubtypes subs =
  let cts = Set.fromList (getType <$> subs)
      all' = Set.unions (cts : (getSubtypes <$> subs))
   in Set.delete thresholdType all'


thresholdCost :: IsCondition c => Word16 -> [c] -> Int
thresholdCost t subs =
  let largest = take (fromIntegral t) $ sortOn (*(-1)) $ getCost <$> subs
   in sum largest + 1024 * length subs


parseThreshold :: IsCondition c => (Word16 -> [c] -> c) -> Message 
                -> ParseASN1 c
parseThreshold construct msg = do
  ffills <- onNextContainer (Container Context 0) $ getMany $ verifyPoly msg
  conds <- onNextContainer (Container Context 1) $ getMany parseCondition
  let t = fromIntegral $ length ffills
  pure $ construct t (conds ++ ffills)


parseCondition :: IsCondition c => ParseASN1 c
parseCondition = withContainerContext $ \tid -> do
  (bs, costbs) <- (,) <$> parseOther 0 <*> parseOther 1
  let cost = fromIntegral $ uIntFromBytes $ BS.unpack costbs
      condPart = anon tid bs cost
  subtypes <- if hasSubtypes $ getType $ condPart mempty
                 then unTypeMask <$> parseOther 2 else pure mempty
  pure $ condPart subtypes


--------------------------------------------------------------------------------
-- | (3) RSA-SHA256 Condition
--

--------------------------------------------------------------------------------
-- | (4) ED25519-SHA256 Condition
--

ed25519Type :: ConditionType
ed25519Type = CT 4 "ed25519-sha-256" False "sha-256"


ed25519Cost :: Int
ed25519Cost = 131072


ed25519Fingerprint :: Ed2.PublicKey -> Fingerprint
ed25519Fingerprint pk = sha256 body
  where body = encodeASN1' DER asn
        asn = [ Start Sequence
              , Other Context 0 $ toData pk
              ]


ed25519Fulfillment :: Ed2.PublicKey -> Ed2.Signature -> Fulfillment
ed25519Fulfillment pk sig = encodeASN1' DER body
  where body = fiveBellsContainer (typeId ed25519Type) [toData pk, toData sig]


parseEd25519 :: (Ed2.PublicKey -> Ed2.Signature -> c) -> Message -> ParseASN1 c
parseEd25519 construct msg = do
  (bspk, bssig) <- (,) <$> parseOther 0 <*> parseOther 1
  (pk,sig) <- either throwParseError pure $
    (,) <$> toKey (Ed2.publicKey bspk)
        <*> toKey (Ed2.signature bssig)
  if Ed2.verify pk msg sig
     then pure $ construct pk sig
     else fail "Ed25519 does not validate"


--------------------------------------------------------------------------------
-- Utilities


sha256 :: BA.ByteArrayAccess a => a -> BS.ByteString
sha256 a = BS.pack $ BA.unpack $ (hash a :: Digest SHA256)


withContainerContext :: (Int -> ParseASN1 a) -> ParseASN1 a
withContainerContext fp = do
  asn <- getNext
  case asn of
    (Start c@(Container Context tid)) -> do
      res <- fp tid
      end <- getNext
      if end /= End c then throwParseError "Failed parsing end"
                      else pure res
    other -> throwParseError ("Not a container context: " ++ show other)


parseOther :: Int -> ParseASN1 BS.ByteString
parseOther n = do
  asn <- getNext
  case asn of
    (Other Context i bs) ->
      if n == i then pure bs
                else throwParseError $ "Invalid context id: " ++ show (n,i)
    other                -> throwParseError "agh" -- TODO

