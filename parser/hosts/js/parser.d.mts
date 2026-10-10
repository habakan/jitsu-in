export class ParserError extends Error {
    /**
     * @param {number} code the module's return value: a P_ERR_* when positive, a UR_ERR_* when negative
     * @param {"P_ERR" | "UR_ERR"} [kind]
     */
    constructor(code: number, kind?: "P_ERR" | "UR_ERR");
    code: number;
}
/** A BIP32 derivation the module read out of the PSBT — BIP380 calls this key origin information.
 *  It is a *claim*: derive the key yourself and check it produces the scriptPubKey before trusting it. */
export class KeyOrigin {
    /**
     * @param {number} fingerprint the master fingerprint this derivation claims
     * @param {number[]} path the raw uint32 path; the high bit means hardened
     */
    constructor(fingerprint: number, path: number[]);
    fingerprint: number;
    path: number[];
    toString(): string;
}
export class Parser {
    /**
     * @param {BufferSource} parserWasm the contents of parser.wasm
     * @param {{ sha256?: string }} [opts] when given, the module must hash to exactly this, or it is
     *   refused. Take the value from the project's `checksums.txt` or a release's `SHA256SUMS`.
     */
    static load(parserWasm: BufferSource, opts?: {
        sha256?: string;
    }): Promise<Parser>;
    /** Synchronous variant, for Node or anywhere compiling on the main thread is fine.
     *  It cannot check a digest: SubtleCrypto has no synchronous form. Use `load` if you want one. */
    /** @param {BufferSource} parserWasm */
    static loadSync(parserWasm: BufferSource): Parser;
    /** A hash in a file nobody checks is documentation. Checking it here makes it a gate. */
    /**
     * @param {BufferSource} bytes
     * @param {string} want
     */
    static "__#private@#assertDigest"(bytes: BufferSource, want: string): Promise<void>;
    /** The module must not be able to call the host at all. Checked before it is instantiated. */
    /** @param {WebAssembly.Module} module */
    static "__#private@#assertNoImports"(module: WebAssembly.Module): void;
    /** @param {WebAssembly.Instance} instance */
    constructor(instance: WebAssembly.Instance);
    /** @type {ParserExports} */
    exports: ParserExports;
    /** @type {Uint8Array} */
    mem: Uint8Array;
    /** @type {DataView} */
    view: DataView;
    /** How many bytes the input buffer takes. */
    get inputCapacity(): number;
    /**
     * Parse a PSBT.
     * @param {Uint8Array} psbt
     * @param {number} fingerprint master fingerprint, big-endian (0x73c5da0a). Not a secret.
     * @returns {Plan}
     */
    parse(psbt: Uint8Array, fingerprint: number): Plan;
    /** Copy the current ABI-v1 plan_t bytes for a matching signer.wasm module. */
    rawPlan(): Uint8Array<ArrayBuffer>;
    /** Drop decoder state before a new animated QR. */
    urReset(): void;
    /**
     * Feed one UR part. Returns the PSBT once the message is complete, otherwise null.
     * @param {string|Uint8Array} part one QR payload
     */
    urReceive(part: string | Uint8Array): Uint8Array<ArrayBuffer> | null;
    /** Parts received so far. For a progress display only. */
    get urProgress(): number;
    /** What the UR urReceive() completed was: "psbt", or "bytes" (a BSMS record or a descriptor, as text). */
    get urKind(): "bytes" | "psbt";
    /**
     * Encode a signed PSBT as animated QR parts.
     * @returns {{ seqLen: number, next: () => string }}
     */
    /**
     * @param {number} psbtLen
     * @param {number} [fragmentLen]
     */
    urEncode(psbtLen: number, fragmentLen?: number): {
        seqLen: number;
        next: () => string;
    };
    /**
     * Encode CBOR signer.wasm made (accountCbor() or multisigCbor()) as crypto-account or crypto-output parts.
     * @param {"crypto-account" | "crypto-output"} type
     * @param {Uint8Array} cbor
     * @param {number} [fragmentLen]
     * @returns {{ seqLen: number, next: () => string }}
     */
    urEncodeCbor(type: "crypto-account" | "crypto-output", cbor: Uint8Array, fragmentLen?: number): {
        seqLen: number;
        next: () => string;
    };
    /**
     * Insert signatures and return the signed PSBT.
     * @param {{input: number, pubkey: Uint8Array, sig: Uint8Array}[]} sigs
     */
    finalize(sigs: {
        input: number;
        pubkey: Uint8Array;
        sig: Uint8Array;
    }[]): Uint8Array<ArrayBuffer>;
    #private;
}
/** What the module read out of the PSBT. Every field is a claim until the host checks it. */
export class Plan {
    /**
     * @param {number} txVersion
     * @param {number} locktime
     * @param {PlanInput[]} inputs
     * @param {PlanOutput[]} outputs
     */
    constructor(txVersion: number, locktime: number, inputs: PlanInput[], outputs: PlanOutput[]);
    txVersion: number;
    locktime: number;
    inputs: PlanInput[];
    outputs: PlanOutput[];
    get totalIn(): bigint;
    get totalOut(): bigint;
    /** Derived from the amounts in the plan, which are claims until the prevtx is checked. */
    get fee(): bigint;
}
/**
 * The exports parser.wasm provides. Declared so that a typo in a name is a type error rather than a
 * call to undefined at runtime.
 */
export type ParserExports = {
    memory: WebAssembly.Memory;
    parser_input: () => number;
    parser_input_cap: () => number;
    parser_parse: (len: number, fingerprint: number) => number;
    parser_plan: () => number;
    parser_sigs: () => number;
    parser_output: () => number;
    parser_prevtx_off: (i: number) => number;
    parser_prevtx_len: (i: number) => number;
    parser_finalize: (n: number) => number;
    parser_ur_reset: () => void;
    parser_ur_receive: (len: number) => number;
    parser_ur_progress: () => number;
    parser_ur_kind: () => number;
    parser_ur_encode_cbor: (kind: number, len: number, fragmentLen: number) => number;
    parser_ur_encode_start: (len: number, fragmentLen: number) => number;
    parser_ur_encode_next: () => number;
};
/**
 * One input of a plan. `amount` and `spk` come from the PSBT's utxo; verifying `prevtx` against
 * `prevTxid` is the only way to know the amount is real.
 */
export type PlanInput = {
    prevTxid: Uint8Array;
    prevVout: number;
    sequence: number;
    amount: bigint;
    spk: Uint8Array;
    key: KeyOrigin | null;
    sighashType: number;
    prevtx: Uint8Array | null;
};
export type PlanOutput = {
    amount: bigint;
    spk: Uint8Array;
    key: KeyOrigin | null;
};
/**
 * A signature for the host to hand back, one per input it signed.
 */
export type Signature = {
    input: number;
    pubkey: Uint8Array;
    sig: Uint8Array;
};
