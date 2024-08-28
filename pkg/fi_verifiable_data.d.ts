/* tslint:disable */
/* eslint-disable */
/**
* Algorithms that used to sign and verify content
*/
export enum Algorithm {
/**
* Sha-256 hash function based HMAC hash algotithm
*/
  HS256 = 0,
/**
* Sha-384 hash function based HMAC hash algotithm
*/
  HS384 = 1,
/**
* Sha-256 hash function based HMAC hash algotithm
*/
  HS512 = 2,
/**
* Sha-256 based RSA algorithm
*/
  RS256 = 3,
/**
* Sha-384 based RSA algorithm
*/
  RS384 = 4,
/**
* Sha-512 based RSA algorithm
*/
  RS512 = 5,
/**
* RSASSA-PSS using SHA-256
*/
  PS256 = 6,
/**
* RSASSA-PSS using SHA-384
*/
  PS384 = 7,
/**
* RSASSA-PSS using SHA-512
*/
  PS512 = 8,
/**
* Elliptic curve with NistP256
*/
  ES256 = 9,
/**
* Elliptic curve with NistP384
*/
  ES384 = 10,
/**
* Elliptic curve with NistP512
*/
  ES512 = 11,
/**
* Elliptic curve with Secp256k1
*/
  ES256K = 12,
/**
* Elliptic curve with Ed25519
*/
  EdDSA = 13,
}
/**
*/
export enum ProofType {
  FiProof = 0,
}
/**
* Algorithm family of [`Algorithm`]
*/
export enum AlgorithmFamily {
/**
* [`crate::algorithms::Algorithm::HS256`]
* [`crate::algorithms::Algorithm::HS384`]
* [`crate::algorithms::Algorithm::HS512`]
*/
  HMAC = 0,
/**
* [`crate::algorithms::Algorithm::ES256`]
* [`crate::algorithms::Algorithm::ES384`]
* [`crate::algorithms::Algorithm::ES512`]
* [`crate::algorithms::Algorithm::ES256K`]
*/
  EC = 1,
/**
* [`crate::algorithms::Algorithm::RS256`]
* [`crate::algorithms::Algorithm::RS384`]
* [`crate::algorithms::Algorithm::RS512`]
* [`crate::algorithms::Algorithm::PS256`]
* [`crate::algorithms::Algorithm::PS384`]
* [`crate::algorithms::Algorithm::PS512`]
*/
  RSA = 2,
/**
* [`crate::algorithms::Algorithm::EdDSA`]
*/
  OKP = 3,
  None = 4,
}
/**
*/
export class DocumentLoader {
  free(): void;
/**
* @param {any} docs
*/
  constructor(docs: any);
/**
* @param {string} url
* @returns {VerificationDocument | undefined}
*/
  getVerificationDocument(url: string): VerificationDocument | undefined;
}
/**
* Signing key for ED25519 algorithm [`crate::algorithms::Algorithm::EdDSA`]
*/
export class EDDSASigningKey {
  free(): void;
}
/**
* Verifying key for ED25519 algorithm
*/
export class EDDSAVerifyingKey {
  free(): void;
}
/**
* Object for error handling
*/
export class Error {
  free(): void;
/**
* @returns {string}
*/
  toString(): string;
}
/**
*/
export class FiError {
  free(): void;
/**
* @param {string} message
*/
  constructor(message: string);
}
/**
* Signing key for HMAC algorithm
*/
export class HMACKey {
  free(): void;
/**
* Create new <b>HMACKey</b> instance
* @param {string} pass
*/
  constructor(pass: string);
/**
* @param {object} value
* @returns {HMACKey}
*/
  static from_js_object(value: object): HMACKey;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES256`]
*/
export class P256SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES256`]
*/
export class P256VerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES256K`]
*/
export class P256kSigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES256K`]
*/
export class P256kVerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES384`]
*/
export class P384SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES384`]
*/
export class P384VerifyingKey {
  free(): void;
}
/**
* Signing key for [`crate::algorithms::Algorithm::ES512`]
*/
export class P512SigningKey {
  free(): void;
}
/**
* Verifying key for [`crate::algorithms::Algorithm::ES512`]
*/
export class P512VerifyingKey {
  free(): void;
}
/**
* Signing key for RSA based algorithms (RSA private key)
*/
export class RsaSigningKey {
  free(): void;
}
/**
* Verifying key for RSA based algorithms (RSA private key)
*/
export class RsaVerifyingKey {
  free(): void;
}
/**
*/
export class VC {
  free(): void;
/**
* @param {string} id
* @param {any} issuer
* @param {any} name
* @param {any} description
* @param {any} valid_until
* @param {(string)[]} contexts
*/
  constructor(id: string, issuer: any, name: any, description: any, valid_until: any, contexts: (string)[]);
/**
* @param {any} issuer
*/
  addIsser(issuer: any): void;
/**
* @param {any} issuer
*/
  setIsser(issuer: any): void;
/**
* @param {any} contexts
*/
  setContext(contexts: any): void;
/**
* @param {any} context
*/
  addContext(context: any): void;
/**
* @param {any} _type
*/
  addType(_type: any): void;
/**
* @param {any} _type
*/
  setType(_type: any): void;
/**
* @param {any} credential_status
*/
  setCredentialStatus(credential_status: any): void;
/**
* @param {any} credential_schema
*/
  setCredentialSchemas(credential_schema: any): void;
/**
* @param {any} expire
*/
  setExpire(expire: any): void;
/**
* @param {any} terms_of_use
*/
  setTermsOfUse(terms_of_use: any): void;
/**
* @param {any} refresh_service
*/
  setRefreshService(refresh_service: any): void;
/**
* @param {any} evidence
*/
  setEvidence(evidence: any): void;
/**
* @returns {any}
*/
  getProof(): any;
/**
* @param {Algorithm} alg
* @param {string} purpose
* @param {VerificationDocument} doc
* @param {ProofType} proof_type
*/
  sign(alg: Algorithm, purpose: string, doc: VerificationDocument, proof_type: ProofType): void;
/**
* @param {VerificationDocument} doc
* @param {ProofType} proof_type
* @returns {boolean}
*/
  verify(doc: VerificationDocument, proof_type: ProofType): boolean;
/**
* @returns {object}
*/
  toObject(): object;
/**
* @returns {string}
*/
  getSignableContent(): string;
/**
* @param {string} key
* @param {any} val
*/
  addField(key: string, val: any): void;
/**
* @param {any} value
* @returns {VC}
*/
  static from(value: any): VC;
}
/**
*/
export class VP {
  free(): void;
/**
* @param {string} id
* @param {any} holder
*/
  constructor(id: string, holder: any);
/**
* @param {any} holder
*/
  setHolder(holder: any): void;
/**
* @param {any} contexts
*/
  setContext(contexts: any): void;
/**
* @param {any} context
*/
  addContext(context: any): void;
/**
* @param {any} _type
*/
  addType(_type: any): void;
/**
* @param {any} _type
*/
  setType(_type: any): void;
/**
* @returns {any}
*/
  getProof(): any;
/**
* @param {VC} verifiable_credential
*/
  addVerifiableCredential(verifiable_credential: VC): void;
/**
* @param {(VC)[]} verifiable_credentials
*/
  setVerifiableCredential(verifiable_credentials: (VC)[]): void;
/**
* @param {Algorithm} alg
* @param {string} purpose
* @param {VerificationDocument} doc
* @param {ProofType} proof_type
*/
  sign(alg: Algorithm, purpose: string, doc: VerificationDocument, proof_type: ProofType): void;
/**
* @param {VerificationDocument} doc
* @param {ProofType} proof_type
* @returns {boolean}
*/
  verify(doc: VerificationDocument, proof_type: ProofType): boolean;
/**
* @returns {object}
*/
  toObject(): object;
/**
* @returns {string}
*/
  getSignableContent(): string;
/**
* @param {string} key
* @param {any} val
*/
  addField(key: string, val: any): void;
/**
* @param {any} value
* @returns {VP}
*/
  static from(value: any): VP;
}
/**
*/
export class VerificationDocument {
  free(): void;
/**
* @param {string} id
* @param {Uint8Array | undefined} [private_key]
* @param {Uint8Array | undefined} [public_key]
*/
  constructor(id: string, private_key?: Uint8Array, public_key?: Uint8Array);
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_vc_free: (a: number, b: number) => void;
  readonly vc_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly vc_addIsser: (a: number, b: number, c: number) => void;
  readonly vc_setContext: (a: number, b: number) => void;
  readonly vc_addContext: (a: number, b: number, c: number) => void;
  readonly vc_addType: (a: number, b: number, c: number) => void;
  readonly vc_setType: (a: number, b: number) => void;
  readonly vc_setCredentialStatus: (a: number, b: number) => void;
  readonly vc_setCredentialSchemas: (a: number, b: number) => void;
  readonly vc_setExpire: (a: number, b: number) => void;
  readonly vc_setTermsOfUse: (a: number, b: number) => void;
  readonly vc_setRefreshService: (a: number, b: number) => void;
  readonly vc_setEvidence: (a: number, b: number) => void;
  readonly vc_getProof: (a: number) => number;
  readonly vc_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly vc_verify: (a: number, b: number, c: number, d: number) => void;
  readonly vc_toObject: (a: number, b: number) => void;
  readonly vc_getSignableContent: (a: number, b: number) => void;
  readonly vc_addField: (a: number, b: number, c: number, d: number) => void;
  readonly vc_from: (a: number, b: number) => void;
  readonly vc_setIsser: (a: number, b: number) => void;
  readonly __wbg_vp_free: (a: number, b: number) => void;
  readonly vp_new: (a: number, b: number, c: number) => number;
  readonly vp_setHolder: (a: number, b: number) => void;
  readonly vp_setContext: (a: number, b: number) => void;
  readonly vp_addContext: (a: number, b: number, c: number) => void;
  readonly vp_addType: (a: number, b: number, c: number) => void;
  readonly vp_setType: (a: number, b: number) => void;
  readonly vp_getProof: (a: number) => number;
  readonly vp_addVerifiableCredential: (a: number, b: number) => void;
  readonly vp_setVerifiableCredential: (a: number, b: number, c: number) => void;
  readonly vp_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly vp_verify: (a: number, b: number, c: number, d: number) => void;
  readonly vp_toObject: (a: number, b: number) => void;
  readonly vp_getSignableContent: (a: number, b: number) => void;
  readonly vp_addField: (a: number, b: number, c: number, d: number) => void;
  readonly vp_from: (a: number, b: number) => void;
  readonly __wbg_verificationdocument_free: (a: number, b: number) => void;
  readonly verificationdocument_new: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly __wbg_documentloader_free: (a: number, b: number) => void;
  readonly documentloader_new: (a: number, b: number) => void;
  readonly documentloader_getVerificationDocument: (a: number, b: number, c: number) => number;
  readonly __wbg_fierror_free: (a: number, b: number) => void;
  readonly fierror_new: (a: number, b: number) => number;
  readonly __wbg_p256ksigningkey_free: (a: number, b: number) => void;
  readonly __wbg_p256kverifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_rsasigningkey_free: (a: number, b: number) => void;
  readonly __wbg_rsaverifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_p256signingkey_free: (a: number, b: number) => void;
  readonly __wbg_p256verifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_p384signingkey_free: (a: number, b: number) => void;
  readonly __wbg_p384verifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_eddsasigningkey_free: (a: number, b: number) => void;
  readonly __wbg_eddsaverifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_error_free: (a: number, b: number) => void;
  readonly error_toString: (a: number, b: number) => void;
  readonly __wbg_p512signingkey_free: (a: number, b: number) => void;
  readonly __wbg_p512verifyingkey_free: (a: number, b: number) => void;
  readonly __wbg_hmackey_free: (a: number, b: number) => void;
  readonly hmackey_new: (a: number, b: number) => number;
  readonly hmackey_from_js_object: (a: number, b: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
