# Crypto Conditions

Targeting spec: draft-thomas-crypto-conditions-02 of December 20, 2016

## Current status

Supports all standard condition types except RSA.

Needs more testing. [Some tests](../test/) exist.

## Design

This approach to Crypto Conditions in Haskell has the goals:

* Simple to understand and work with
* Easily extensible

The bottleneck to achieving these goals is extensibility; Haskell does not
support dynamic dispatch like OOP languages, and runtime type casting
in Haskell is very unnatural and somewhat unsafe.

The solution is to decouple the condition type from the implementation,
such that the core algorithms and serialization can work with instances
of an "IsCondition" class, and a polymorphic data type can be implemented
separately to support the desired condition types and behaviours.

The module [Network.CryptoConditions](./Network/CryptoConditions.hs) supports the standard
condition types, library authors wishing to extend CryptoConditions
should copy and paste this file into their own project and define their own
Condition type.

