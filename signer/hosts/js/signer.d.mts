export namespace OWNER {
    let EXTERNAL: number;
    let CHANGE: number;
    let SELF: number;
}
export namespace TEXT_KIND {
    let ADDRESS: number;
    let OP_RETURN: number;
    let SCRIPT: number;
}
/** CORE_ERR_* by value, as signer/docs/abi.md lists them.
 *  @type {Record<number, string>} */
export const ERRORS: Record<number, string>;
export class SignerError extends Error {
    /**
     * @param {string} stage which call refused: "review", "display", "sign" or "xpub"
     * @param {number} code a CORE_ERR_* value
     */
    constructor(stage: string, code: number);
    stage: string;
    code: number;
}
export class Signer {
    /** `sha256` refuses any module that is not the build you expected. For a module that will hold a
     *  key, pinning it is the difference between running your signer and running someone else's. */
    /**
     * @param {BufferSource} signerWasm
     * @param {{ sha256?: string }} [opts]
     */
    static load(signerWasm: BufferSource, opts?: {
        sha256?: string;
    }): Promise<Signer>;
    static get LAYOUT(): {
        plan: {
            size: number;
            nInputs: number;
            nOutputs: number;
        };
        review: {
            size: number;
            totalIn: number;
            totalOut: number;
            fee: number;
            owner: number;
            willSign: number;
            nSign: number;
        };
        display: {
            size: number;
            fee: number;
            spend: number;
            nOutputs: number;
            outputs: number;
            outSize: number;
            outAmount: number;
            outOwner: number;
            outTextKind: number;
            outText: number;
            outTextCap: number;
        };
        sig: {
            size: number;
            input: number;
            pubkey: number;
            sigLen: number;
            sig: number;
        };
        message: {
            size: number;
            address: number;
            textKind: number;
            text: number;
            textCap: number;
        };
        limits: {
            maxInputs: number;
            maxOutputs: number;
            xpubMax: number;
            descMax: number;
            prevtxMax: number;
        };
    };
    /** @param {WebAssembly.Instance} instance */
    constructor(instance: WebAssembly.Instance);
    /** Call once, before anything else. `testnet` also covers signet. */
    init({ testnet }?: {
        testnet?: boolean | undefined;
    }): this;
    /** Derives the key from a BIP39 mnemonic. PBKDF2 2048 rounds, about half a second.
     *  Takes NFKD-normalised UTF-8 bytes, not strings, because a string cannot be cleared; both arrays
     *  are zeroed before this returns, whether or not it succeeds. */
    /**
     * @param {Uint8Array} mnemonic
     * @param {Uint8Array} [passphrase]
     */
    seedFromMnemonic(mnemonic: Uint8Array, passphrase?: Uint8Array): this;
    /** Derives the key from a SeedQR: the Standard digits as ASCII bytes, or the CompactSeedQR's raw
     *  bytes. The words stay inside the module, so confirm what was loaded by its fingerprint. Both
     *  arrays are zeroed before this returns. */
    /**
     * @param {Uint8Array} payload
     * @param {Uint8Array} [passphrase]
     */
    seedFromSeedQR(payload: Uint8Array, passphrase?: Uint8Array): this;
    /** A new mnemonic from 16 to 32 bytes of entropy (12 to 24 words), as UTF-8 bytes to show and then
     *  clear. Nothing is loaded. `entropy` is zeroed, and so is the module's copy of the words. */
    /** @param {Uint8Array} entropy */
    mnemonicFromEntropy(entropy: Uint8Array): Uint8Array<ArrayBuffer>;
    /** A new mnemonic from dice rolls, the characters 1 to 6: at least 50 for 12 words, 99 for 24. The
     *  entropy is SHA-256 of the rolls. `rolls` is zeroed. */
    /**
     * @param {Uint8Array} rolls
     * @param {12 | 24} [words]
     */
    mnemonicFromDice(rolls: Uint8Array, words?: 12 | 24): Uint8Array<ArrayBuffer>;
    /** The SeedQR of a 12 or 24 word mnemonic, to show as a backup: the Standard digits as ASCII (QR
     *  numeric mode), or with `compact` the CompactSeedQR's bytes (QR byte mode). It is the seed itself,
     *  so clear it once shown. `mnemonic` is zeroed, and so is the module's copy. */
    /**
     * @param {Uint8Array} mnemonic
     * @param {{ compact?: boolean }} [opts]
     */
    seedQRFromMnemonic(mnemonic: Uint8Array, { compact }?: {
        compact?: boolean;
    }): Uint8Array<ArrayBuffer>;
    /** The BIP85 child mnemonic of the loaded seed (m/83696968'/39'/0'/words'/index'), as UTF-8 bytes to
     *  show and then clear. English; `words` is 12, 18 or 24. The module's copy is zeroed. */
    /** @param {{ words?: 12 | 18 | 24, index?: number }} [opts] */
    bip85Mnemonic({ words, index }?: {
        words?: 12 | 18 | 24;
        index?: number;
    }): Uint8Array<ArrayBuffer>;
    /** For a seed you already have. 64 bytes. */
    /** @param {Uint8Array} seed */
    loadSeed(seed: Uint8Array): this;
    /** Clears the key and everything derived from it. Call it when you are done, not when you
     *  remember to. */
    unload(): void;
    get fingerprint(): string;
    /** The plan parser.wasm produced, copied in verbatim. Loading a plan invalidates any review. */
    /** @param {Uint8Array} planBytes */
    setPlan(planBytes: Uint8Array): this;
    /** The non_witness_utxo for each input, in the same order as the plan's inputs. `null` for an
     *  input that had none. */
    /** @param {(Uint8Array | null)[]} prevTxs */
    setPrevTxs(prevTxs: (Uint8Array | null)[]): this;
    /** Re-derives the keys and checks the plan against them. Nothing is signed until this passes. */
    review(): {
        totalIn: bigint;
        totalOut: bigint;
        fee: bigint;
        nSign: number;
        owner: number[];
        willSign: number[];
    };
    /** What to put in front of the person approving. Every string here was built inside the module
     *  from the plan's bytes, so it cannot be a string the PSBT chose. */
    display(): {
        fee: bigint;
        spend: bigint;
        outputs: {
            amount: bigint;
            owner: number;
            textKind: number;
            text: string;
        }[];
    };
    /** Signs, and only the plan review() was shown. Returns one entry per signature, ready to hand to
     *  parser.wasm's signature buffer.
     *
     *  One review permits exactly one signing: the module clears its own approval afterwards, so a
     *  second call without reviewing again is refused. One approval, one signature. */
    sign(): {
        input: number;
        pubkey: Uint8Array<ArrayBuffer>;
        sig: Uint8Array<ArrayBuffer>;
        raw: Uint8Array<ArrayBuffer>;
    }[];
    /** Which of our addresses this is: receive (chain 0) first, then change, indices 0 to count-1. Takes
     *  a bare address or a BIP21 URI; P2SH-P2WPKH, P2WPKH and P2TR only. Returns null when it is not found. */
    /**
     * @param {string} address
     * @param {{ account?: number, count?: number }} [opts]
     * @returns {{ chain: number, index: number } | null}
     */
    findAddress(address: string, { account, count }?: {
        account?: number;
        count?: number;
    }): {
        chain: number;
        index: number;
    } | null;
    /** What to show before signing a message with BIP137: the address of m/purpose'/coin'/account'/chain/index
     *  (purpose 49 or 84), and the message, as it is when it is printable ASCII and in hex otherwise.
     *  Approving it permits one messageSign(). */
    /**
     * @param {Uint8Array} message
     * @param {{ purpose?: 49 | 84, account?: number, chain?: number, index?: number }} [opts]
     */
    messageReview(message: Uint8Array, { purpose, account, chain, index }?: {
        purpose?: 49 | 84;
        account?: number;
        chain?: number;
        index?: number;
    }): {
        address: string;
        textKind: "message" | "hex";
        text: string;
    };
    /** The BIP137 signature of the message messageReview() showed: 65 bytes, header then r and s. Most
     *  wallets want it in base64. */
    messageSign(): Uint8Array<ArrayBuffer>;
    /** The account xpub and its sh(wpkh()) (purpose 49), wpkh() (84) or tr() (86) descriptor, for making a watch-only
     *  wallet elsewhere. `account` is below 2^31. */
    xpub({ purpose, account }?: {
        purpose?: number | undefined;
        account?: number | undefined;
    }): {
        xpub: string;
        descriptor: string;
    };
    #private;
}
/**
 * The exports signer.wasm provides. Declared so that a typo in a name is a type error rather than a
 * call to undefined at runtime.
 */
export type SignerExports = {
    memory: WebAssembly.Memory;
    signer_input: () => number;
    signer_input_cap: () => number;
    signer_plan: () => number;
    signer_prevtx: () => number;
    signer_review_output: () => number;
    signer_display_output: () => number;
    signer_sigs: () => number;
    signer_xpub_output: () => number;
    signer_desc_output: () => number;
    signer_init: (testnet: number) => number;
    signer_seed_from_mnemonic: (mnLen: number, passLen: number) => number;
    signer_seed_from_seedqr: (qrLen: number, passLen: number) => number;
    signer_load_seed: () => number;
    signer_unload: () => void;
    signer_fingerprint: () => number;
    signer_set_prevtx: (i: number, off: number, len: number) => number;
    signer_review: () => number;
    signer_display: () => number;
    signer_sign: () => number;
    signer_xpub: (purpose: number, account: number) => number;
    signer_find_address: (len: number, account: number, count: number) => number;
    signer_mnemonic_output: () => number;
    signer_mnemonic_from_entropy: (len: number) => number;
    signer_mnemonic_from_dice: (len: number, words: number) => number;
    signer_seedqr_output: () => number;
    signer_seedqr_from_mnemonic: (mnLen: number, compact: number) => number;
    signer_bip85_mnemonic: (words: number, index: number) => number;
    signer_message_output: () => number;
    signer_message_sig: () => number;
    signer_message_review: (len: number, purpose: number, account: number, chain: number, index: number) => number;
    signer_message_sign: () => number;
};
/**
 * What review() reports. `owner` has one entry per output, `willSign` one per input.
 */
export type Review = {
    totalIn: bigint;
    totalOut: bigint;
    fee: bigint;
    nSign: number;
    owner: number[];
    willSign: number[];
};
/**
 * One line of what to show. Every string here was built inside the module from the plan's bytes.
 */
export type DisplayOutput = {
    amount: bigint;
    owner: number;
    textKind: number;
    text: string;
};
/**
 * `spend` is the total of external outputs; ours and change are excluded.
 */
export type Display = {
    fee: bigint;
    spend: bigint;
    outputs: DisplayOutput[];
};
/**
 * Hand `raw` to parser.wasm's signature buffer; `sig` and `pubkey` are for showing or checking.
 */
export type Signature = {
    input: number;
    pubkey: Uint8Array;
    sig: Uint8Array;
    raw: Uint8Array;
};
