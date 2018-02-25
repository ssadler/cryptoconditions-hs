{-# LANGUAGE OverloadedStrings #-}

module TestVectors
  ( vectorSuite
  ) where


import Test.Tasty
import Test.Tasty.HUnit

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.Aeson
import Data.Aeson.Types
import Data.Aeson.Quick
import Data.Maybe
import Data.Monoid
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)

import System.IO.Unsafe

import Network.CryptoConditions
import Network.CryptoConditions.Encoding

import TestSupport


vectorSuite :: TestTree
vectorSuite = testGroup "fiveBells"
  [ testVectors "0000_test-minimal-preimage.json"
  , testVectors "0001_test-minimal-prefix.json"
  , testVectors "0002_test-minimal-threshold.json"
  , testVectors "0004_test-minimal-ed25519.json"
  , testVectors "0006_test-basic-prefix.json"
  , testVectors "0012_test-basic-threshold-schroedinger.json"
  , testVectors "0017_test-advanced-notarized-receipt-multiple-notaries.json"
  ]


testVectors :: String -> TestTree
testVectors file = testGroup file
  [ testCase "encodeCondition" $ encodeCondition cond @?= condBin
  , testCase "encodeFulfillment" $ encodeFulfillment cond @?= Just ffillBin
  , testCase "getConditionURI" $ getConditionURI cond @?= condUri
  , testCase "validate" $ validate condUri cond msg @?= True
  , testCase "decodeCondition" $
      let econd = decodeCondition condBin :: Either String Condition
       in (getConditionURI <$> econd) @?= Right condUri
  ]
  where
    val = unsafePerformIO $ do
      let path = "ext/crypto-conditions/test-vectors/valid/" <> file
      fromJust . decodeStrict <$> BS.readFile path
    cond = val .! "{json}" :: Condition
    condBin = fromB16 $ val .! "{conditionBinary}"
    ffillBin = fromB16 $ val .! "{fulfillment}"
    condUri = val .! "{conditionUri}"
    msg = encodeUtf8 $ val .! "{message}"


fromB16 :: T.Text -> BS.ByteString
fromB16 t = let (r,"") = B16.decode $ encodeUtf8 t
             in r
