-- Specification theorems for the `wireTypes` module.
--
-- Same pattern as Spec/MessageCellType.lean and Spec/RelayCommand.lean:
-- each wire-vocabulary DU has a code function, an inverse parser, and
-- a round-trip theorem proving the two are mutual inverses on valid
-- inputs.

import Generated.WireTypes
import Thales.TS.Runtime

open Thales.TS

namespace Spec.WireTypes

open _root_.WireTypes

deriving instance DecidableEq for AddressType
deriving instance DecidableEq for LinkSpecifierType
deriving instance DecidableEq for HandshakeType
deriving instance DecidableEq for RelayResolvedType

----------------------------------------------------------------------------
-- AddressType
----------------------------------------------------------------------------

theorem addressTypeCode_in_set (a : AddressType) :
    addressTypeCode a = 4 ∨ addressTypeCode a = 6 := by
  cases a <;> (first | (left; decide) | (right; decide))

/-- **Round-trip.** -/
theorem addressTypeFromCode_addressTypeCode (a : AddressType) :
    addressTypeFromCode (addressTypeCode a) = some a := by
  cases a <;> decide

theorem addressTypeFromCode_zero :
    addressTypeFromCode 0 = none := by decide

theorem addressTypeFromCode_five :
    addressTypeFromCode 5 = none := by decide

theorem addressTypeFromCode_seven :
    addressTypeFromCode 7 = none := by decide

----------------------------------------------------------------------------
-- LinkSpecifierType
----------------------------------------------------------------------------

theorem linkSpecifierTypeCode_in_range (t : LinkSpecifierType) :
    0 ≤ linkSpecifierTypeCode t ∧ linkSpecifierTypeCode t ≤ 3 := by
  cases t <;> (constructor <;> decide)

/-- **Round-trip.** -/
theorem linkSpecifierTypeFromCode_linkSpecifierTypeCode (t : LinkSpecifierType) :
    linkSpecifierTypeFromCode (linkSpecifierTypeCode t) = some t := by
  cases t <;> decide

theorem linkSpecifierTypeFromCode_isSome
    (n : Int) (hlo : 0 ≤ n) (hhi : n ≤ 3) :
    linkSpecifierTypeFromCode n ≠ none := by
  have henum : n = 0 ∨ n = 1 ∨ n = 2 ∨ n = 3 := by omega
  rcases henum with h | h | h | h <;> subst h <;> decide

theorem linkSpecifierTypeFromCode_neg :
    linkSpecifierTypeFromCode (-1) = none := by decide

theorem linkSpecifierTypeFromCode_above :
    linkSpecifierTypeFromCode 4 = none := by decide

----------------------------------------------------------------------------
-- HandshakeType
----------------------------------------------------------------------------

theorem handshakeTypeCode_in_set (h : HandshakeType) :
    handshakeTypeCode h = 0 ∨ handshakeTypeCode h = 2 := by
  cases h <;> (first | (left; decide) | (right; decide))

/-- **Round-trip.** -/
theorem handshakeTypeFromCode_handshakeTypeCode (h : HandshakeType) :
    handshakeTypeFromCode (handshakeTypeCode h) = some h := by
  cases h <;> decide

/-- Code 1 (FAST, removed in current protocol) is not in the supported
    vocabulary. -/
theorem handshakeTypeFromCode_one :
    handshakeTypeFromCode 1 = none := by decide

theorem handshakeTypeFromCode_three :
    handshakeTypeFromCode 3 = none := by decide

theorem handshakeTypeFromCode_neg :
    handshakeTypeFromCode (-1) = none := by decide

----------------------------------------------------------------------------
-- RelayResolvedType
----------------------------------------------------------------------------

theorem relayResolvedTypeCode_in_set (t : RelayResolvedType) :
    relayResolvedTypeCode t = 0 ∨
    relayResolvedTypeCode t = 4 ∨
    relayResolvedTypeCode t = 6 ∨
    relayResolvedTypeCode t = 240 ∨
    relayResolvedTypeCode t = 241 := by
  cases t <;> first
    | (left; decide)
    | (right; left; decide)
    | (right; right; left; decide)
    | (right; right; right; left; decide)
    | (right; right; right; right; decide)

/-- **Round-trip.** -/
theorem relayResolvedTypeFromCode_relayResolvedTypeCode (t : RelayResolvedType) :
    relayResolvedTypeFromCode (relayResolvedTypeCode t) = some t := by
  cases t <;> decide

theorem relayResolvedTypeFromCode_one : relayResolvedTypeFromCode 1 = none := by decide
theorem relayResolvedTypeFromCode_five : relayResolvedTypeFromCode 5 = none := by decide
theorem relayResolvedTypeFromCode_239 : relayResolvedTypeFromCode 239 = none := by decide
theorem relayResolvedTypeFromCode_242 : relayResolvedTypeFromCode 242 = none := by decide

/-- **Error characterization.** A resolved-record type is an error iff
    its wire code is 240 (transient) or 241 (permanent). -/
theorem isResolvedError_iff (t : RelayResolvedType) :
    isResolvedError t = true ↔
      relayResolvedTypeCode t = 240 ∨ relayResolvedTypeCode t = 241 := by
  cases t <;> simp [isResolvedError, relayResolvedTypeCode]

/-- AddressType and RelayResolvedType agree on the IP-family codes. -/
theorem addressType_relayResolvedType_ipv4_agree :
    addressTypeCode (.IPv4) = relayResolvedTypeCode (.IPv4) := by decide

theorem addressType_relayResolvedType_ipv6_agree :
    addressTypeCode (.IPv6) = relayResolvedTypeCode (.IPv6) := by decide

end Spec.WireTypes
