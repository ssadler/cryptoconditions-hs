{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.HUnit

import TestFiveBells
import TestStandard


main :: IO ()
main = defaultMain $ testGroup "Tests" [ fiveBellsSuite
                                       , standardTests
                                       ]


