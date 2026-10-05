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
        limits: {
            maxInputs: number;
            maxOutputs: number;
            xpubMax: number;
            descMax: number;
        };
    };
    /** @param {WebAssembly.Instance} instance */
    constructor(instance: WebAssembly.Instance);
    /** Call once, before anything else. `testnet` also covers signet. */
    init({ testnet }?: {
        testnet?: boolean | undefined;
    }): this;
    /** Derives the key from a BIP39 mnemonic. PBKDF2 2048 rounds, about half a second.
     *  The module wipes its own input buffer; the strings you passed in are yours to deal with. */
    /**
     * @param {string} mnemonic
     * @param {string} [passphrase]
     */
    seedFromMnemonic(mnemonic: string, passphrase?: string): this;
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
    /** The account xpub and an output descriptor, for making a watch-only wallet elsewhere. */
    xpub(): {
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
    signer_load_seed: () => number;
    signer_unload: () => void;
    signer_fingerprint: () => number;
    signer_set_prevtx: (i: number, off: number, len: number) => number;
    signer_review: () => number;
    signer_display: () => number;
    signer_sign: () => number;
    signer_xpub: () => number;
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
