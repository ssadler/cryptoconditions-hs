{-# LANGUAGE OverloadedStrings #-}


module Network.CryptoConditions.Impl where


import           Crypto.Hash
import qualified Crypto.PubKey.Ed25519 as Ed2

import           Data.ASN1.BinaryEncoding
import           Data.ASN1.BinaryEncoding.Raw
import           Data.ASN1.Encoding
import           Data.ASN1.Parse
import           Data.ASN1.Types
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import           Data.List (sortOn)
import           Data.Maybe
import           Data.Monoid
import qualified Data.Set as Set
import qualified Data.Text as T
import           Data.Text.Encoding (decodeUtf8)
import           Data.Word

import           Network.CryptoConditions.Encoding


--------------------------------------------------------------------------------
-- | Class of things that are conditions
--
class Show c => IsCondition c where
  getCost :: c -> Int
  getType :: c -> ConditionType
  getFingerprint :: c -> Fingerprint
  getFulfillmentASN :: c -> Maybe [ASN1]
  getSubtypes :: c -> Set.Set ConditionType
  parseFulfillment :: Int -> ParseASN1 c
  verifyMessage :: c -> Message -> Bool
  anon :: Int -> BS.ByteString -> Int -> Set.Set Int -> c


-- Parameter aliases
type Message = BS.ByteString
type Fulfillment = BS.ByteString
type Preimage = BS.ByteString
type Prefix = BS.ByteString
type Fingerprint = BS.ByteString


encodeCondition :: IsCondition c => c -> BS.ByteString
encodeCondition = encodeASN1' DER . getConditionASN


getConditionASN :: IsCondition c => c -> [ASN1]
getConditionASN c =
  let ct = getType c
      fingerprint = getFingerprint c
      costBs = BS.pack $ bytesOfUInt $ fromIntegral $ getCost c
      subtypes = toBitString $ Set.map typeId $ getSubtypes c
      body = [fingerprint, costBs] ++
             if hasSubtypes ct then [subtypes] else []
   in asnChoice (typeId ct) $ asnData body


getConditionURI :: IsCondition c => c -> T.Text
getConditionURI c =
  let ct = getType c
      f = decodeUtf8 $ b64EncodeStripped $ getFingerprint c
      cost = T.pack $ show $ getCost c
      subtypes = if hasSubtypes ct
                    then "&subtypes=" <> typeNames (getSubtypes c)
                    else ""
   in "ni:///" <> hashFunc ct <> ";" <> f
       <> "?fpt=" <> typeName ct <> "&cost="
       <> cost <> subtypes


encodeFulfillment :: IsCondition c => c -> Maybe Fulfillment
encodeFulfillment cond = encodeASN1' DER <$> getFulfillmentASN cond


encodeFulfillmentBase64 :: IsCondition c => c -> Maybe T.Text
encodeFulfillmentBase64 cond = decodeUtf8 . B64.encode <$> encodeFulfillment cond


decodeFulfillment :: IsCondition c => Fulfillment -> Either String c
decodeFulfillment bs = parseASN1 bs parsePoly


decodeFulfillmentBase64 :: IsCondition c => Fulfillment -> Either String c
decodeFulfillmentBase64 = decodeFulfillment . B64.decodeLenient


decodeCondition :: IsCondition c => BS.ByteString -> Either String c
decodeCondition bs = parseASN1 bs parseCondition


parsePoly :: IsCondition c => ParseASN1 c
parsePoly = withContainerContext parseFulfillment


validate :: IsCondition c => T.Text -> c -> Message -> Bool
validate condUri ffill msg =
  verifyMessage ffill msg && getConditionURI ffill == condUri


parseCondition :: IsCondition c => ParseASN1 c
parseCondition = withContainerContext $ \tid -> do
  (bs, costbs) <- (,) <$> parseOther 0 <*> parseOther 1
  let cost = fromIntegral $ uIntFromBytes $ BS.unpack costbs
      condPart = anon tid bs cost
  subtypes <- if hasSubtypes $ getType $ condPart mempty
                 then fromBitString <$> parseOther 2 else pure mempty
  pure $ condPart subtypes


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


typeNames :: Set.Set ConditionType -> T.Text
typeNames = T.intercalate "," . map typeName . Set.toAscList


--------------------------------------------------------------------------------
-- | (0) Preimage Condition
--

preimageType :: ConditionType
preimageType = CT 0 "preimage-sha-256" False "sha-256"


preimageFulfillmentASN :: BS.ByteString -> [ASN1]
preimageFulfillmentASN pre = asnChoice 0 $ asnData [pre]


preimageCost :: BS.ByteString -> Int
preimageCost = BS.length


preimageFingerprint :: Preimage -> Fingerprint
preimageFingerprint = sha256


parsePreimage :: (Preimage -> c) -> ParseASN1 c
parsePreimage construct = construct <$> parseOther 0


-- | The preimage is assumed to be correct if it has been provided;
--   it'll show up during URI comparison if it's wrong.
verifyPreimage :: Preimage -> Message -> Bool
verifyPreimage _ _ = True


--------------------------------------------------------------------------------
-- | (1) Prefix condition


prefixType :: ConditionType
prefixType = CT 1 "prefix-sha-256" True "sha-256"


prefixCost :: IsCondition c => Prefix -> Int -> c -> Int
prefixCost pre maxMessageLength c =
  BS.length pre + getCost c + 1024 + maxMessageLength


prefixFingerprint :: IsCondition c => Prefix -> Int -> c -> Fingerprint
prefixFingerprint pre mml cond = hashASN $ asn
  where
    mmlbs = BS.pack $ bytesOfUInt $ fromIntegral mml
    condAsn = getConditionASN cond
    asn = asnSequence Sequence $ asnData [pre, mmlbs] ++ asnChoice 2 condAsn


prefixFulfillmentASN :: IsCondition c => Prefix -> Int -> c -> Maybe [ASN1]
prefixFulfillmentASN pre mml cond =
  let mmlbs = BS.pack $ bytesOfUInt $ fromIntegral mml
      getAsn subasn =
        asnChoice 1 $ asnData [pre, mmlbs] ++ asnChoice 2 subasn
   in getAsn <$> getFulfillmentASN cond


prefixSubtypes :: IsCondition c => c -> Set.Set ConditionType
prefixSubtypes cond =
  let cts = Set.singleton $ getType cond
      all' = Set.union cts $ getSubtypes cond
   in Set.delete prefixType all'


parsePrefix :: IsCondition c => (Prefix -> Int -> c -> c) -> ParseASN1 c
parsePrefix construct = do
  (pre, mmlbs) <- (,) <$> parseOther 0 <*> parseOther 1
  let mml = fromIntegral $ uIntFromBytes $ BS.unpack mmlbs
  cond <- parseContainer 2 parsePoly
  pure $ construct pre mml cond


verifyPrefix :: IsCondition c => Prefix -> Int -> c -> Message -> Bool
verifyPrefix prefix mml cond msg =
  let ok = mml >= BS.length msg
   in ok && verifyMessage cond (prefix <> msg)


--------------------------------------------------------------------------------
-- | (2) Threshold condition
--

thresholdType :: ConditionType
thresholdType = CT 2 "threshold-sha-256" True "sha-256"


thresholdFulfillmentASN :: IsCondition c => Word16 -> [c] -> Maybe [ASN1]
thresholdFulfillmentASN t subs =
  let ti = fromIntegral t
      withFf = zip subs (getFulfillmentASN <$> subs)
      byCost = sortOn ffillCost withFf
      ffills = take ti $ catMaybes $ snd <$> byCost
      conds = getConditionASN . fst <$> drop ti byCost
      asn = asnChoice 2 $ asnChoice 0 (concat ffills) ++ asnChoice 1 (concat conds)
   in if length ffills == ti then Just asn else Nothing
  where
    -- order by has ffill then cost of ffill
    ffillCost (c, Just _) = (0::Int, getCost c)
    ffillCost _           = (1, 0)


thresholdFingerprint :: IsCondition c => Word16 -> [c] -> Fingerprint
thresholdFingerprint t subs =
  let asns = getConditionASN <$> subs
   in thresholdFingerprintFromAsns t asns


thresholdFingerprintFromAsns :: Word16 -> [[ASN1]] -> Fingerprint
thresholdFingerprintFromAsns t asns = 
  let subs' = x690SortAsn asns
      asn = asnSequence Sequence $
              asnData [BS.pack $ bytesOfUInt $ fromIntegral t] ++
              asnChoice 1 (concat subs')
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


parseThreshold :: IsCondition c => (Word16 -> [c] -> c) -> ParseASN1 c
parseThreshold construct = do
  ffills <- parseContainer 0 $ getMany parsePoly
  conds <- parseContainer 1 $ getMany parseCondition
  let t = fromIntegral $ length ffills
  pure $ construct t (conds ++ ffills)


verifyThreshold :: IsCondition c => Word16 -> [c] -> Message -> Bool
verifyThreshold m subs msg =
  let m' = fromIntegral m
      doVerify c = verifyMessage c msg
   in m' == length (take m' $ filter (==True) $ map doVerify subs)


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
ed25519Fingerprint pk =
  hashASN $ asnSequence Sequence $ asnData [toData pk]


ed25519FulfillmentASN :: Ed2.PublicKey -> Ed2.Signature -> [ASN1]
ed25519FulfillmentASN pk sig = asnChoice 4 $ asnData [toData pk, toData sig]


parseEd25519 :: (Ed2.PublicKey -> Ed2.Signature -> c) -> ParseASN1 c
parseEd25519 construct = do
  (bspk, bssig) <- (,) <$> parseOther 0 <*> parseOther 1
  either throwParseError pure $
    construct <$> toKey (Ed2.publicKey bspk)
              <*> toKey (Ed2.signature bssig)


verifyEd25519 :: Ed2.PublicKey -> Ed2.Signature -> Message -> Bool
verifyEd25519 pk = flip (Ed2.verify pk)


--------------------------------------------------------------------------------
-- Utilities


sha256 :: BA.ByteArrayAccess a => a -> BS.ByteString
sha256 a = BS.pack $ BA.unpack $ (hash a :: Digest SHA256)


hashASN :: [ASN1] -> Fingerprint
hashASN = sha256 . encodeASN1' DER


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


parseContainer :: Int -> ParseASN1 a -> ParseASN1 a
parseContainer = onNextContainer . Container Context


parseOther :: Int -> ParseASN1 BS.ByteString
parseOther n = do
  asn <- getNext
  case asn of
    (Other Context i bs) ->
      if n == i then pure bs
                else throwParseError $ "Invalid context id: " ++ show (n,i)
    notOther -> throwParseError ("Unexpected element: " ++ show notOther)
