{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.HUnit

import TestStandard
import TestUnits
import TestVectors


main :: IO ()
main = defaultMain $ testGroup "Tests" [ unitTests
                                       , standardTests
                                       , vectorSuite
                                       ]


