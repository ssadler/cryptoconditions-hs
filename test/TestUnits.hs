{-# LANGUAGE OverloadedStrings #-}

module TestUnits
  ( unitTests
  ) where

import Data.Set as Set

import Test.Tasty
import Test.Tasty.HUnit

import Network.CryptoConditions.Encoding

import TestSupport


unitTests :: TestTree
unitTests = testGroup "testUnits"
  [ testBitStrings
  ]


testBitStrings :: TestTree
testBitStrings = testGroup "bitString" $
  let sets = [ [0]
             , [1]
             , [0, 1]
             , [2, 7]
             , [15, 32]
             , [155]
             ]
      test set = assertEqual "bit string equal" set (fromBitString $ toBitString set)
   in (\s -> testCase (show s) (test $ Set.fromList s)) <$> sets
