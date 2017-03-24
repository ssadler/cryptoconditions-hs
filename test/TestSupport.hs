{-# LANGUAGE OverloadedStrings #-}

module TestSupport where


import Crypto.Error
import Crypto.PubKey.Ed25519

import Network.CryptoConditions


import qualified Data.ByteString as BS


alice, bob, aliceSK, bobSK :: BS.ByteString
alice = "\DC1\ETXf\236\&5!L\147\EOT\b|%\DLE\237y\fp\187\DC4:\229\ETX\247\234X\219\187\196\SO\NAK8\220"
aliceSK = "*J\255(*-B'Z\168\151\DLE\227j\DC139&\DLE\136\ETB/\ETX\SOH9_Y'\227>1\254"
bob = "s|l\222<\204\DLE\219(#~)\142\245HE\STXdC\219.\181DE\EOT\166c\179\133\DC2\130;"
bobSK = "C\SOH\NAK 6P\151\165|\156\144of-B\174\245h\166\188\135\158\SO\195\b)\253\168\f\221\205\RS"


ed2Alice, ed2Bob :: Condition
ed2Alice = ed25519Condition pkAlice
ed2Bob = ed25519Condition pkBob


pkAlice, pkBob :: PublicKey
pkAlice = throwCryptoError $ publicKey alice
pkBob = throwCryptoError $ publicKey bob


skAlice :: SecretKey
skAlice = toSecret aliceSK


toPub :: BS.ByteString -> PublicKey
toPub = throwCryptoError . publicKey


toSig :: BS.ByteString -> Signature
toSig = throwCryptoError . signature


toSecret :: BS.ByteString -> SecretKey
toSecret = throwCryptoError . secretKey
