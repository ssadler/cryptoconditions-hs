{-# LANGUAGE OverloadedStrings #-}

module TestSupport where

import Crypto.Error
import Crypto.PubKey.Ed25519

import Network.CryptoConditions

import Data.ByteString


umsg :: ByteString
umsg = "\240\159\141\186\\uD83C\\uDF7A"


ed2Alice, ed2Bob, ed2Eve :: Condition
ed2Alice = ed25519Condition pkAlice
ed2Bob = ed25519Condition pkBob
ed2Eve = ed25519Condition pkEve


ed2BobF, ed2EveF :: Condition
ed2BobF = fulfillEd25519 pkBob sigBob ed2Bob
ed2EveF = fulfillEd25519 pkEve sigEve ed2Eve


pkAlice, pkBob :: PublicKey
pkAlice = toPublic skAlice
pkBob = toPublic skBob
pkEve = toPublic skEve


skAlice, skBob, skEve :: SecretKey
skAlice = toSecret "B\SOH\NAK 6P\151\165|\156\144of-B\174\245h\166\188\135\158\SO\195\b)\253\168\f\221\205\RS"
skBob = toSecret "C\SOH\NAK 6P\151\165|\156\144of-B\174\245h\166\188\135\158\SO\195\b)\253\168\f\221\205\RS"
skEve = toSecret "D\SOH\NAK 6P\151\165|\156\144of-B\174\245h\166\188\135\158\SO\195\b)\253\168\f\221\205\RS"


toSecret :: ByteString -> SecretKey
toSecret = throwCryptoError . secretKey


sigAlice, sigBob, sigEve :: Signature
sigAlice = sign skAlice pkAlice umsg
sigBob = sign skBob pkBob umsg
sigEve = sign skEve pkEve umsg


toPub :: ByteString -> PublicKey
toPub = throwCryptoError . publicKey


toSig :: ByteString -> Signature
toSig = throwCryptoError . signature
