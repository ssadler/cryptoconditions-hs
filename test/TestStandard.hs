{-# LANGUAGE OverloadedStrings #-}

module TestStandard
  ( standardTests
  ) where

import Test.Tasty
import Test.Tasty.HUnit

import Network.CryptoConditions

import TestSupport


standardTests :: TestTree
standardTests = testGroup "testStandard"
  [ testFulfill "Test ed25519" ed2Alice
  
  , testFulfill "Test 1 of 1" $
      Threshold 1 [ed2Alice]

  , testFulfill "Test 1 of 2" $
      Threshold 1 [ed2Alice, ed2Bob]

  , testFulfill "Test 2 of 2" $
      Threshold 2 [ed2Alice, ed2BobF]

  , testFulfill "Test 2 of 3" $
      Threshold 2 [ed2Alice, ed2BobF, ed2Eve]

  , testFulfill "Test 3 of 3" $
      Threshold 3 [ed2Alice, ed2BobF, ed2EveF]

  , testFulfill "Test nested" $
      let subcond = Threshold 2 [ed2Alice, preimageCondition "a", ed2Eve]
       in Threshold 2 [ed2BobF, subcond]

  , testFulfill "Test prefixed" $
      Prefix "a" 20 ed2Alice
  ]


-- | Takes a condition which just requires Alice to sign in
--   order to validate
testFulfill :: String -> Condition -> TestTree
testFulfill name cond = testCase name $ do
  let msg = umsg
      uri = getConditionURI cond
      badFfill = fulfillEd25519 pkAlice skEve umsg cond
      (Just ffillBin) = encodeFulfillment badFfill
      goodFfill = fulfillEd25519 pkAlice skAlice umsg cond
      econd = decodeFulfillment ffillBin :: Either String Condition
  assertEqual "can not get fulfillment payload without signature"
      Nothing $ encodeFulfillment cond
  assertEqual "get uri from good fulfillment"
    (Right uri) $ getConditionURI <$> econd
  assertBool "wrong sig right message does not validate" $
      not $ validate uri badFfill msg
  assertBool "wrong msg right sig does not validate" $
      not $ validate uri goodFfill "b"
  assertBool "right sig right message does validate" $
      validate uri goodFfill msg
