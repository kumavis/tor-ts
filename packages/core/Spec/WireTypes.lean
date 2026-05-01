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

end Spec.WireTypes
