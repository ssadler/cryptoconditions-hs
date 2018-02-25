{-# LANGUAGE OverloadedStrings #-}

module Network.CryptoConditions.Encoding
  ( x690SortAsn
  , b64EncodeStripped
  , b64DecodeStripped
  , bytesOfUInt
  , uIntFromBytes
  , asnData
  , asnChoice
  , asnSequence
  , toData
  , toKey
  , parseASN1
  , toBitString
  , fromBitString
  ) where


import Crypto.Error (CryptoFailable(..))

import Data.ASN1.BinaryEncoding
import Data.ASN1.BinaryEncoding.Raw
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Parse
import Data.ASN1.Types
import Data.Bits
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8 as C8
import Data.List (sortOn)
import Data.Monoid
import qualified Data.Set as Set
import Data.Word


b64EncodeStripped :: BS.ByteString -> BS.ByteString
b64EncodeStripped bs =
  let b64 = B64.encode bs
   in case C8.elemIndex '=' b64 of Just i -> BS.take i b64
                                   Nothing -> b64


b64DecodeStripped :: BS.ByteString -> Either String BS.ByteString
b64DecodeStripped bs =
  let r = 4 - mod (BS.length bs) 4
      n = if r == 4 then 0 else r
   in B64.decode $ bs <> C8.replicate n '='


x690SortAsn :: [[ASN1]] -> [[ASN1]]
x690SortAsn = sortOn (\a -> let b = encodeASN1' DER a in (BS.length b, b))


asnSequence :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asnSequence c args = [Start c] ++ args ++ [End c]


asnChoice :: Integral i => i -> [ASN1] -> [ASN1]
asnChoice tid asn =
  let c = Container Context $ fromIntegral tid
   in asnSequence c asn


asnData :: [BS.ByteString] -> [ASN1]
asnData bss = [Other Context i s | (i,s) <- zip [0..] bss]


bytesOfUInt :: Integer -> [Word8]
bytesOfUInt = reverse . list
  where list i | i <= 0xff = [fromIntegral i]
               | otherwise = (fromIntegral i .&. 0xff)
                             : list (i `shiftR` 8)


uIntFromBytes :: [Word8] -> Integer
uIntFromBytes ws =
  let ns = zip (fromIntegral <$> reverse ws) [0..]
   in foldl (\r (n,o) -> r .|. (n `shiftL` (o*8))) 0 ns


parseASN1 :: BS.ByteString -> ParseASN1 a -> Either String a
parseASN1 bs act = showErr decoded >>= runParseASN1 act
  where decoded = decodeASN1 DER $ BL.fromStrict bs
        showErr = either (Left . show) Right


toKey :: CryptoFailable a -> Either String a
toKey r = case r of
   CryptoPassed a -> return a
   CryptoFailed e -> Left $ show e


toData :: BA.ByteArrayAccess a => a -> BS.ByteString
toData = BS.pack . BA.unpack


-- TODO: Support larger bitstrings

toBitString :: Set.Set Int -> BS.ByteString
toBitString types =
    let words = Set.map fromIntegral types
        bitArray = foldl bitArraySetBit (BitArray 32 "\0") words
        maxId = foldl max 0 types
        bitsUnused = fromIntegral $ 7 - mod maxId 8
     in BS.singleton bitsUnused <> bitArrayGetData bitArray


fromBitString :: BS.ByteString -> Set.Set Int
fromBitString maskbs = Set.fromList $
  let [_, w] = fromIntegral <$> BS.unpack maskbs :: [Int]
   in filter (\i -> 0 /= w .&. (shiftL 1 (7-i))) [0..7]
