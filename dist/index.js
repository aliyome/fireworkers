// node_modules/.pnpm/superstruct@1.0.3/node_modules/superstruct/dist/index.mjs
var StructError = class extends TypeError {
  constructor(failure, failures) {
    let cached;
    const { message: message2, explanation, ...rest } = failure;
    const { path } = failure;
    const msg = path.length === 0 ? message2 : `At path: ${path.join(".")} -- ${message2}`;
    super(explanation ?? msg);
    if (explanation != null)
      this.cause = msg;
    Object.assign(this, rest);
    this.name = this.constructor.name;
    this.failures = () => {
      return cached ?? (cached = [failure, ...failures()]);
    };
  }
};
function isIterable(x) {
  return isObject(x) && typeof x[Symbol.iterator] === "function";
}
function isObject(x) {
  return typeof x === "object" && x != null;
}
function print(value) {
  if (typeof value === "symbol") {
    return value.toString();
  }
  return typeof value === "string" ? JSON.stringify(value) : `${value}`;
}
function shiftIterator(input) {
  const { done, value } = input.next();
  return done ? void 0 : value;
}
function toFailure(result, context, struct, value) {
  if (result === true) {
    return;
  } else if (result === false) {
    result = {};
  } else if (typeof result === "string") {
    result = { message: result };
  }
  const { path, branch } = context;
  const { type } = struct;
  const { refinement, message: message2 = `Expected a value of type \`${type}\`${refinement ? ` with refinement \`${refinement}\`` : ""}, but received: \`${print(value)}\`` } = result;
  return {
    value,
    type,
    refinement,
    key: path[path.length - 1],
    path,
    branch,
    ...result,
    message: message2
  };
}
function* toFailures(result, context, struct, value) {
  if (!isIterable(result)) {
    result = [result];
  }
  for (const r of result) {
    const failure = toFailure(r, context, struct, value);
    if (failure) {
      yield failure;
    }
  }
}
function* run(value, struct, options = {}) {
  const { path = [], branch = [value], coerce = false, mask: mask2 = false } = options;
  const ctx = { path, branch };
  if (coerce) {
    value = struct.coercer(value, ctx);
    if (mask2 && struct.type !== "type" && isObject(struct.schema) && isObject(value) && !Array.isArray(value)) {
      for (const key in value) {
        if (struct.schema[key] === void 0) {
          delete value[key];
        }
      }
    }
  }
  let status = "valid";
  for (const failure of struct.validator(value, ctx)) {
    failure.explanation = options.message;
    status = "not_valid";
    yield [failure, void 0];
  }
  for (let [k, v, s] of struct.entries(value, ctx)) {
    const ts = run(v, s, {
      path: k === void 0 ? path : [...path, k],
      branch: k === void 0 ? branch : [...branch, v],
      coerce,
      mask: mask2,
      message: options.message
    });
    for (const t of ts) {
      if (t[0]) {
        status = t[0].refinement != null ? "not_refined" : "not_valid";
        yield [t[0], void 0];
      } else if (coerce) {
        v = t[1];
        if (k === void 0) {
          value = v;
        } else if (value instanceof Map) {
          value.set(k, v);
        } else if (value instanceof Set) {
          value.add(v);
        } else if (isObject(value)) {
          if (v !== void 0 || k in value)
            value[k] = v;
        }
      }
    }
  }
  if (status !== "not_valid") {
    for (const failure of struct.refiner(value, ctx)) {
      failure.explanation = options.message;
      status = "not_refined";
      yield [failure, void 0];
    }
  }
  if (status === "valid") {
    yield [void 0, value];
  }
}
var Struct = class {
  constructor(props) {
    const { type, schema, validator, refiner, coercer = (value) => value, entries = function* () {
    } } = props;
    this.type = type;
    this.schema = schema;
    this.entries = entries;
    this.coercer = coercer;
    if (validator) {
      this.validator = (value, context) => {
        const result = validator(value, context);
        return toFailures(result, context, this, value);
      };
    } else {
      this.validator = () => [];
    }
    if (refiner) {
      this.refiner = (value, context) => {
        const result = refiner(value, context);
        return toFailures(result, context, this, value);
      };
    } else {
      this.refiner = () => [];
    }
  }
  /**
   * Assert that a value passes the struct's validation, throwing if it doesn't.
   */
  assert(value, message2) {
    return assert(value, this, message2);
  }
  /**
   * Create a value with the struct's coercion logic, then validate it.
   */
  create(value, message2) {
    return create(value, this, message2);
  }
  /**
   * Check if a value passes the struct's validation.
   */
  is(value) {
    return is(value, this);
  }
  /**
   * Mask a value, coercing and validating it, but returning only the subset of
   * properties defined by the struct's schema.
   */
  mask(value, message2) {
    return mask(value, this, message2);
  }
  /**
   * Validate a value with the struct's validation logic, returning a tuple
   * representing the result.
   *
   * You may optionally pass `true` for the `withCoercion` argument to coerce
   * the value before attempting to validate it. If you do, the result will
   * contain the coerced result when successful.
   */
  validate(value, options = {}) {
    return validate(value, this, options);
  }
};
function assert(value, struct, message2) {
  const result = validate(value, struct, { message: message2 });
  if (result[0]) {
    throw result[0];
  }
}
function create(value, struct, message2) {
  const result = validate(value, struct, { coerce: true, message: message2 });
  if (result[0]) {
    throw result[0];
  } else {
    return result[1];
  }
}
function mask(value, struct, message2) {
  const result = validate(value, struct, { coerce: true, mask: true, message: message2 });
  if (result[0]) {
    throw result[0];
  } else {
    return result[1];
  }
}
function is(value, struct) {
  const result = validate(value, struct);
  return !result[0];
}
function validate(value, struct, options = {}) {
  const tuples = run(value, struct, options);
  const tuple = shiftIterator(tuples);
  if (tuple[0]) {
    const error = new StructError(tuple[0], function* () {
      for (const t of tuples) {
        if (t[0]) {
          yield t[0];
        }
      }
    });
    return [error, void 0];
  } else {
    const v = tuple[1];
    return [void 0, v];
  }
}
function define(name, validator) {
  return new Struct({ type: name, schema: null, validator });
}
function boolean() {
  return define("boolean", (value) => {
    return typeof value === "boolean";
  });
}
function date() {
  return define("date", (value) => {
    return value instanceof Date && !isNaN(value.getTime()) || `Expected a valid \`Date\` object, but received: ${print(value)}`;
  });
}
function never() {
  return define("never", () => false);
}
function number() {
  return define("number", (value) => {
    return typeof value === "number" && !isNaN(value) || `Expected a number, but received: ${print(value)}`;
  });
}
function object(schema) {
  const knowns = schema ? Object.keys(schema) : [];
  const Never = never();
  return new Struct({
    type: "object",
    schema: schema ? schema : null,
    *entries(value) {
      if (schema && isObject(value)) {
        const unknowns = new Set(Object.keys(value));
        for (const key of knowns) {
          unknowns.delete(key);
          yield [key, value[key], schema[key]];
        }
        for (const key of unknowns) {
          yield [key, value[key], Never];
        }
      }
    },
    validator(value) {
      return isObject(value) || `Expected an object, but received: ${print(value)}`;
    },
    coercer(value) {
      return isObject(value) ? { ...value } : value;
    }
  });
}
function string() {
  return define("string", (value) => {
    return typeof value === "string" || `Expected a string, but received: ${print(value)}`;
  });
}

// src/schemas.ts
var TIMESTAMP_REGEX = /^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))$/g;
var date_schema = date();
var string_schema = string();
var boolean_schema = boolean();
var number_schema = number();
var object_schema = object();
var geo_point_schema = object({
  latitude: number(),
  longitude: number()
});
var timestamp_schema = define("timestamp", (value) => {
  if (!is(value, string_schema))
    return false;
  return TIMESTAMP_REGEX.test(value) && is(new Date(value), date_schema);
});

// src/fields.ts
var convert_field_to_value = (field_value) => {
  if (Array.isArray(field_value)) {
    return {
      arrayValue: {
        values: field_value.map(convert_field_to_value)
      }
    };
  }
  const [, geo_point_value] = validate(field_value, geo_point_schema);
  if (geo_point_value)
    return { geoPointValue: geo_point_value };
  if (is(field_value, object_schema)) {
    const entries = Object.entries(field_value).map(
      ([key, value]) => [key, convert_field_to_value(value)]
    );
    return {
      mapValue: {
        fields: Object.fromEntries(entries)
      }
    };
  }
  if (is(field_value, timestamp_schema))
    return { timestampValue: field_value };
  if (is(field_value, boolean_schema))
    return { booleanValue: field_value };
  if (is(field_value, number_schema))
    return { integerValue: field_value };
  if (is(field_value, string_schema))
    return { stringValue: field_value };
  return { nullValue: "NULL_VALUE" };
};
var create_document_from_fields = (fields) => {
  const entries = Object.entries(fields).map(
    ([key, value]) => [key, convert_field_to_value(value)]
  );
  const document = { fields: Object.fromEntries(entries) };
  return document;
};
var extract_fields_from_document = (document) => {
  const { name, fields = {}, ...timestamps } = document;
  const entries = Object.entries(fields).map(
    ([key, value]) => [key, extract_value(value)]
  );
  const new_fields = Object.fromEntries(entries);
  const new_document = {
    ...timestamps,
    id: extract_id_from_name(name),
    fields: new_fields
  };
  return new_document;
};
var extract_value = (value) => {
  const { arrayValue, mapValue, ...primitiveValue } = value;
  if (arrayValue)
    return extract_array_value(arrayValue);
  if (mapValue)
    return extract_map_value(mapValue);
  return extract_primitive_value(primitiveValue);
};
var extract_primitive_value = (primitiveValues) => Object.values(primitiveValues)[0];
var extract_array_value = ({ values = [] }) => values.map(extract_value);
var extract_map_value = ({ fields = {} }) => {
  const entries = Object.entries(fields).map(([key, value]) => [key, extract_value(value)]);
  return Object.fromEntries(entries);
};
var extract_id_from_name = (name = "") => name.match(/[^/]+$/)?.[0] || name;

// src/utils.ts
var FIRESTORE_ENDPOINT = "https://firestore.googleapis.com";
var get_firestore_endpoint = (project_id) => `${FIRESTORE_ENDPOINT}/v1/projects/${project_id}/databases/(default)/documents`;

// src/create.ts
var create2 = async ({ jwt, project_id }, ...args) => {
  const endpoint = get_firestore_endpoint(project_id);
  const collection_path = args.slice(0, -1).join("/");
  const fields = args.at(-1);
  const payload = create_document_from_fields(fields);
  const response = await fetch(`${endpoint}/${collection_path}`, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      Authorization: `Bearer ${jwt}`
    }
  });
  const data = await response.json();
  if ("error" in data)
    throw new Error(data.error.message);
  const document = extract_fields_from_document(data);
  return document;
};

// src/get.ts
var get = async ({ jwt, project_id }, ...args) => {
  const endpoint = get_firestore_endpoint(project_id);
  const document_path = args.join("/");
  const response = await fetch(`${endpoint}/${document_path}`, {
    headers: {
      Authorization: `Bearer ${jwt}`
    }
  });
  const data = await response.json();
  if ("error" in data)
    throw new Error(data.error.message);
  const document = extract_fields_from_document(data);
  return document;
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/webcrypto.js
var webcrypto_default = crypto;
var isCryptoKey = (key) => key instanceof CryptoKey;

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach((buffer) => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/base64url.js
var encodeBase64 = (input) => {
  let unencoded = input;
  if (typeof unencoded === "string") {
    unencoded = encoder.encode(unencoded);
  }
  const CHUNK_SIZE = 32768;
  const arr = [];
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
  }
  return btoa(arr.join(""));
};
var encode = (input) => {
  return encodeBase64(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/util/errors.js
var JOSEError = class extends Error {
  static get code() {
    return "ERR_JOSE_GENERIC";
  }
  constructor(message2) {
    var _a;
    super(message2);
    this.code = "ERR_JOSE_GENERIC";
    this.name = this.constructor.name;
    (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
  }
};
var JOSENotSupported = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JOSE_NOT_SUPPORTED";
  }
  static get code() {
    return "ERR_JOSE_NOT_SUPPORTED";
  }
};
var JWSInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWS_INVALID";
  }
  static get code() {
    return "ERR_JWS_INVALID";
  }
};
var JWTInvalid = class extends JOSEError {
  constructor() {
    super(...arguments);
    this.code = "ERR_JWT_INVALID";
  }
  static get code() {
    return "ERR_JWT_INVALID";
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/random.js
var random_default = webcrypto_default.getRandomValues.bind(webcrypto_default);

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/env.js
function isCloudflareWorkers() {
  return typeof WebSocketPair !== "undefined" || typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers" || typeof EdgeRuntime !== "undefined" && EdgeRuntime === "vercel";
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg2) {
  switch (alg2) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkSigCryptoKey(key, alg2, ...usages) {
  switch (alg2) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC"))
        throw unusable("HMAC");
      const expected = parseInt(alg2.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5"))
        throw unusable("RSASSA-PKCS1-v1_5");
      const expected = parseInt(alg2.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS"))
        throw unusable("RSA-PSS");
      const expected = parseInt(alg2.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case (isCloudflareWorkers() && "EdDSA"): {
      if (!isAlgorithm(key.algorithm, "NODE-ED25519"))
        throw unusable("NODE-ED25519");
      break;
    }
    case "EdDSA": {
      if (key.algorithm.name !== "Ed25519" && key.algorithm.name !== "Ed448") {
        throw unusable("Ed25519 or Ed448");
      }
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA"))
        throw unusable("ECDSA");
      const expected = getNamedCurve(alg2);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected)
        throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types2) {
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor && actual.constructor.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
var invalid_key_input_default = (actual, ...types2) => {
  return message("Key must be ", actual, ...types2);
};
function withAlg(alg2, actual, ...types2) {
  return message(`Key for the ${alg2} algorithm must be `, actual, ...types2);
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/is_key_like.js
var is_key_like_default = (key) => {
  return isCryptoKey(key);
};
var types = ["CryptoKey"];

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/is_disjoint.js
var isDisjoint = (...headers) => {
  const sources = headers.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
};
var is_disjoint_default = isDisjoint;

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject2(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/check_key_length.js
var check_key_length_default = (alg2, key) => {
  if (alg2.startsWith("RS") || alg2.startsWith("PS")) {
    const { modulusLength } = key.algorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(`${alg2} requires key modulusLength to be 2048 bits or larger`);
    }
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/asn1.js
var findOid = (keyData, oid, from = 0) => {
  if (from === 0) {
    oid.unshift(oid.length);
    oid.unshift(6);
  }
  let i = keyData.indexOf(oid[0], from);
  if (i === -1)
    return false;
  const sub = keyData.subarray(i, i + oid.length);
  if (sub.length !== oid.length)
    return false;
  return sub.every((value, index) => value === oid[index]) || findOid(keyData, oid, i + 1);
};
var getNamedCurve2 = (keyData) => {
  switch (true) {
    case findOid(keyData, [42, 134, 72, 206, 61, 3, 1, 7]):
      return "P-256";
    case findOid(keyData, [43, 129, 4, 0, 34]):
      return "P-384";
    case findOid(keyData, [43, 129, 4, 0, 35]):
      return "P-521";
    case findOid(keyData, [43, 101, 110]):
      return "X25519";
    case findOid(keyData, [43, 101, 111]):
      return "X448";
    case findOid(keyData, [43, 101, 112]):
      return "Ed25519";
    case findOid(keyData, [43, 101, 113]):
      return "Ed448";
    default:
      throw new JOSENotSupported("Invalid or unsupported EC Key Curve or OKP Key Sub Type");
  }
};
var genericImport = async (replace, keyFormat, pem, alg2, options) => {
  var _a;
  let algorithm;
  let keyUsages;
  const keyData = new Uint8Array(atob(pem.replace(replace, "")).split("").map((c) => c.charCodeAt(0)));
  const isPublic = keyFormat === "spki";
  switch (alg2) {
    case "PS256":
    case "PS384":
    case "PS512":
      algorithm = { name: "RSA-PSS", hash: `SHA-${alg2.slice(-3)}` };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    case "RS256":
    case "RS384":
    case "RS512":
      algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${alg2.slice(-3)}` };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      algorithm = {
        name: "RSA-OAEP",
        hash: `SHA-${parseInt(alg2.slice(-3), 10) || 1}`
      };
      keyUsages = isPublic ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
      break;
    case "ES256":
      algorithm = { name: "ECDSA", namedCurve: "P-256" };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    case "ES384":
      algorithm = { name: "ECDSA", namedCurve: "P-384" };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    case "ES512":
      algorithm = { name: "ECDSA", namedCurve: "P-521" };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      const namedCurve = getNamedCurve2(keyData);
      algorithm = namedCurve.startsWith("P-") ? { name: "ECDH", namedCurve } : { name: namedCurve };
      keyUsages = isPublic ? [] : ["deriveBits"];
      break;
    }
    case (isCloudflareWorkers() && "EdDSA"): {
      const namedCurve = getNamedCurve2(keyData).toUpperCase();
      algorithm = { name: `NODE-${namedCurve}`, namedCurve: `NODE-${namedCurve}` };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    }
    case "EdDSA":
      algorithm = { name: getNamedCurve2(keyData) };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    default:
      throw new JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value');
  }
  return webcrypto_default.subtle.importKey(keyFormat, keyData, algorithm, (_a = options === null || options === void 0 ? void 0 : options.extractable) !== null && _a !== void 0 ? _a : false, keyUsages);
};
var fromPKCS8 = (pem, alg2, options) => {
  return genericImport(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, "pkcs8", pem, alg2, options);
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/key/import.js
async function importPKCS8(pkcs8, alg2, options) {
  if (typeof pkcs8 !== "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) {
    throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
  }
  return fromPKCS8(pkcs8, alg2, options);
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/check_key_type.js
var symmetricTypeCheck = (alg2, key) => {
  if (key instanceof Uint8Array)
    return;
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg2, key, ...types, "Uint8Array"));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${types.join(" or ")} instances for symmetric algorithms must be of type "secret"`);
  }
};
var asymmetricTypeCheck = (alg2, key, usage) => {
  if (!is_key_like_default(key)) {
    throw new TypeError(withAlg(alg2, key, ...types));
  }
  if (key.type === "secret") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (usage === "sign" && key.type === "public") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm signing must be of type "private"`);
  }
  if (usage === "decrypt" && key.type === "public") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm decryption must be of type "private"`);
  }
  if (key.algorithm && usage === "verify" && key.type === "private") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm verifying must be of type "public"`);
  }
  if (key.algorithm && usage === "encrypt" && key.type === "private") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm encryption must be of type "public"`);
  }
};
var checkKeyType = (alg2, key, usage) => {
  const symmetric = alg2.startsWith("HS") || alg2 === "dir" || alg2.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg2);
  if (symmetric) {
    symmetricTypeCheck(alg2, key);
  } else {
    asymmetricTypeCheck(alg2, key, usage);
  }
};
var check_key_type_default = checkKeyType;

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    } else if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default = validateCrit;

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/jwe/flattened/encrypt.js
var unprotected = Symbol();

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/subtle_dsa.js
function subtleDsa(alg2, algorithm) {
  const hash = `SHA-${alg2.slice(-3)}`;
  switch (alg2) {
    case "HS256":
    case "HS384":
    case "HS512":
      return { hash, name: "HMAC" };
    case "PS256":
    case "PS384":
    case "PS512":
      return { hash, name: "RSA-PSS", saltLength: alg2.slice(-3) >> 3 };
    case "RS256":
    case "RS384":
    case "RS512":
      return { hash, name: "RSASSA-PKCS1-v1_5" };
    case "ES256":
    case "ES384":
    case "ES512":
      return { hash, name: "ECDSA", namedCurve: algorithm.namedCurve };
    case (isCloudflareWorkers() && "EdDSA"):
      const { namedCurve } = algorithm;
      return { name: namedCurve, namedCurve };
    case "EdDSA":
      return { name: algorithm.name };
    default:
      throw new JOSENotSupported(`alg ${alg2} is not supported either by JOSE or your javascript runtime`);
  }
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/get_sign_verify_key.js
function getCryptoKey(alg2, key, usage) {
  if (isCryptoKey(key)) {
    checkSigCryptoKey(key, alg2, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    if (!alg2.startsWith("HS")) {
      throw new TypeError(invalid_key_input_default(key, ...types));
    }
    return webcrypto_default.subtle.importKey("raw", key, { hash: `SHA-${alg2.slice(-3)}`, name: "HMAC" }, false, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/epoch.js
var epoch_default = (date2) => Math.floor(date2.getTime() / 1e3);

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/lib/secs.js
var minute = 60;
var hour = minute * 60;
var day = hour * 24;
var week = day * 7;
var year = day * 365.25;
var REGEX = /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;
var secs_default = (str) => {
  const matched = REGEX.exec(str);
  if (!matched) {
    throw new TypeError("Invalid time period format");
  }
  const value = parseFloat(matched[1]);
  const unit = matched[2].toLowerCase();
  switch (unit) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
      return Math.round(value);
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
      return Math.round(value * minute);
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
      return Math.round(value * hour);
    case "day":
    case "days":
    case "d":
      return Math.round(value * day);
    case "week":
    case "weeks":
    case "w":
      return Math.round(value * week);
    default:
      return Math.round(value * year);
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/runtime/sign.js
var sign = async (alg2, key, data) => {
  const cryptoKey = await getCryptoKey(alg2, key, "sign");
  check_key_length_default(alg2, cryptoKey);
  const signature = await webcrypto_default.subtle.sign(subtleDsa(alg2, cryptoKey.algorithm), cryptoKey, data);
  return new Uint8Array(signature);
};
var sign_default = sign;

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/jws/flattened/sign.js
var FlattenedSign = class {
  constructor(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError("payload must be an instance of Uint8Array");
    }
    this._payload = payload;
  }
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this._unprotectedHeader = unprotectedHeader;
    return this;
  }
  async sign(key, options) {
    if (!this._protectedHeader && !this._unprotectedHeader) {
      throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
    }
    if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader)) {
      throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
    }
    const joseHeader = {
      ...this._protectedHeader,
      ...this._unprotectedHeader
    };
    const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
    let b64 = true;
    if (extensions.has("b64")) {
      b64 = this._protectedHeader.b64;
      if (typeof b64 !== "boolean") {
        throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
      }
    }
    const { alg: alg2 } = joseHeader;
    if (typeof alg2 !== "string" || !alg2) {
      throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    check_key_type_default(alg2, key, "sign");
    let payload = this._payload;
    if (b64) {
      payload = encoder.encode(encode(payload));
    }
    let protectedHeader;
    if (this._protectedHeader) {
      protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
    } else {
      protectedHeader = encoder.encode("");
    }
    const data = concat(protectedHeader, encoder.encode("."), payload);
    const signature = await sign_default(alg2, key, data);
    const jws = {
      signature: encode(signature),
      payload: ""
    };
    if (b64) {
      jws.payload = decoder.decode(payload);
    }
    if (this._unprotectedHeader) {
      jws.header = this._unprotectedHeader;
    }
    if (this._protectedHeader) {
      jws.protected = decoder.decode(protectedHeader);
    }
    return jws;
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/jws/compact/sign.js
var CompactSign = class {
  constructor(payload) {
    this._flattened = new FlattenedSign(payload);
  }
  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  async sign(key, options) {
    const jws = await this._flattened.sign(key, options);
    if (jws.payload === void 0) {
      throw new TypeError("use the flattened module for creating JWS with b64: false");
    }
    return `${jws.protected}.${jws.payload}.${jws.signature}`;
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/jwt/produce.js
var ProduceJWT = class {
  constructor(payload) {
    if (!isObject2(payload)) {
      throw new TypeError("JWT Claims Set MUST be an object");
    }
    this._payload = payload;
  }
  setIssuer(issuer) {
    this._payload = { ...this._payload, iss: issuer };
    return this;
  }
  setSubject(subject) {
    this._payload = { ...this._payload, sub: subject };
    return this;
  }
  setAudience(audience) {
    this._payload = { ...this._payload, aud: audience };
    return this;
  }
  setJti(jwtId) {
    this._payload = { ...this._payload, jti: jwtId };
    return this;
  }
  setNotBefore(input) {
    if (typeof input === "number") {
      this._payload = { ...this._payload, nbf: input };
    } else {
      this._payload = { ...this._payload, nbf: epoch_default(new Date()) + secs_default(input) };
    }
    return this;
  }
  setExpirationTime(input) {
    if (typeof input === "number") {
      this._payload = { ...this._payload, exp: input };
    } else {
      this._payload = { ...this._payload, exp: epoch_default(new Date()) + secs_default(input) };
    }
    return this;
  }
  setIssuedAt(input) {
    if (typeof input === "undefined") {
      this._payload = { ...this._payload, iat: epoch_default(new Date()) };
    } else {
      this._payload = { ...this._payload, iat: input };
    }
    return this;
  }
};

// node_modules/.pnpm/jose@4.11.2/node_modules/jose/dist/browser/jwt/sign.js
var SignJWT = class extends ProduceJWT {
  setProtectedHeader(protectedHeader) {
    this._protectedHeader = protectedHeader;
    return this;
  }
  async sign(key, options) {
    var _a;
    const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
    sig.setProtectedHeader(this._protectedHeader);
    if (Array.isArray((_a = this._protectedHeader) === null || _a === void 0 ? void 0 : _a.crit) && this._protectedHeader.crit.includes("b64") && this._protectedHeader.b64 === false) {
      throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
    }
    return sig.sign(key, options);
  }
};

// src/init.ts
var alg = "RS256";
var aud = `${FIRESTORE_ENDPOINT}/`;
var init = async ({
  client_email,
  private_key,
  private_key_id,
  uid,
  project_id,
  claims = {}
}) => {
  const sign_key = await importPKCS8(private_key.replace(/\\n/g, "\n"), alg);
  const jwt = await new SignJWT({
    aud,
    uid,
    claims,
    sub: client_email,
    iss: client_email
  }).setProtectedHeader({ alg, kid: private_key_id }).setIssuedAt().setExpirationTime("1h").sign(sign_key);
  return {
    project_id,
    jwt
  };
};

// src/query.ts
var query = async ({ jwt, project_id }, query2, ...args) => {
  const endpoint = get_firestore_endpoint(project_id);
  const document_path = args.length === 0 ? "" : "/" + args.join("/");
  const payload = {
    structuredQuery: query2
  };
  const response = await fetch(`${endpoint}${document_path}:runQuery`, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      Authorization: `Bearer ${jwt}`
    }
  });
  const data = await response.json();
  const documents = data.reduce((acc, { document }) => {
    if (!document)
      return acc;
    acc.push(extract_fields_from_document(document));
    return acc;
  }, []);
  return documents;
};

// src/remove.ts
var remove = async ({ jwt, project_id }, ...args) => {
  const endpoint = get_firestore_endpoint(project_id);
  const document_path = args.join("/");
  const response = await fetch(`${endpoint}/${document_path}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${jwt}`
    }
  });
  return response.ok;
};

// src/update.ts
var update = async ({ jwt, project_id }, ...args) => {
  const endpoint = get_firestore_endpoint(project_id);
  const collection_path = args.slice(0, -1).join("/");
  const fields = args.at(-1);
  const payload = create_document_from_fields(fields);
  const response = await fetch(`${endpoint}/${collection_path}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
    headers: {
      Authorization: `Bearer ${jwt}`
    }
  });
  const data = await response.json();
  if ("error" in data)
    throw new Error(data.error.message);
  const document = extract_fields_from_document(data);
  return document;
};
export {
  create2 as create,
  get,
  init,
  query,
  remove,
  update
};
