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
  [ testCase "testFulfillSimple" $ do
      let cond = Threshold 1 [preimageCondition "ah", ed2Alice]
          (Just ffill) = getFulfillment cond
          condUri = getURI <$> readStandardFulfillment "" ffill
      condUri @?= Right (getURI cond)

  , testCase "testFulfillNestedThresholds" $ do
      let t1 = Threshold 1 [preimageCondition "ah"]
          t2 = Threshold 1 [ed25519Condition pkAlice]
          cond = Threshold 1 [t1, t2]
          (Just ffill) = getFulfillment cond
          condUri = getURI <$> readStandardFulfillment "" ffill
      condUri @?= Right (getURI cond)
  ]

