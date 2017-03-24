{-# LANGUAGE OverloadedStrings #-}

module TestStandard
  ( standardTests
  ) where

import Crypto.PubKey.Ed25519

import Data.ByteString

import Test.Tasty
import Test.Tasty.HUnit


import Network.CryptoConditions

import TestSupport


standardTests :: TestTree
standardTests = testGroup "testStandard"
  [ testCase "testFulfillSimple" $ do
      let cond = Threshold 1 [preimageCondition "ah", ed2Alice]
          (Just ffill) = getFulfillment cond
          condUri = getURI <$> readStandardFulfillment (Just "s") ffill
      condUri @?= Right (getURI cond)

  , testCase "testFulfillNestedThresholds" $ do
      let t1 = Threshold 1 [preimageCondition "ah"]
          t2 = Threshold 1 [ed25519Condition pkAlice]
          cond = Threshold 1 [t1, t2]
          (Just ffill) = getFulfillment cond
          condUri = getURI <$> readStandardFulfillment (Just "") ffill
      condUri @?= Right (getURI cond)
  
  , testCase "testUnicode" $ do 
      let msg = "\240\159\141\186\\uD83C\\uDF7A" :: ByteString
          sig = sign skAlice pkAlice msg
          cond = fulfillEd25519 pkAlice sig ed2Alice
          (Just ffill) = getFulfillment cond
          condUri = getURI <$> readStandardFulfillment (Just msg) ffill
      condUri @?= Right (getURI cond)
  ]
