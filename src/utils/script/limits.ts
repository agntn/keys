/** Largest redeem script a P2SH spend can push, the consensus limit on one stack item. */
export const MAX_P2SH_SCRIPT_SIZE = 520;

/** Largest witness script a P2WSH spend can run, the consensus limit on a script. */
export const MAX_P2WSH_SCRIPT_SIZE = 10_000;

/** Most keys `OP_CHECKMULTISIG` takes. */
export const MAX_MULTISIG_KEYS = 20;
