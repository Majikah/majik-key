// SLIP-44 coin type 0 = Bitcoin mainnet — the path any standard wallet
// (Electrum, Sparrow, hardware wallets) derives by default from this mnemonic.
export const MAJIK_BITCOIN_STANDARD_PATH = "m/84'/0'/0'/0/0";

// Unregistered/private coin-type index — domain-separates Majik's default
// Bitcoin key from a user's "real" BTC wallet, while remaining 100% standard
// BIP-32 math (just a different branch of the same tree).
export const MAJIK_BITCOIN_DOMAIN_PATH = "m/84'/1989'/0'/0/0";
