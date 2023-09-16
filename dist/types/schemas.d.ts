export declare const string_schema: import("superstruct").Struct<string, null>;
export declare const boolean_schema: import("superstruct").Struct<boolean, null>;
export declare const number_schema: import("superstruct").Struct<number, null>;
export declare const object_schema: import("superstruct").Struct<Record<string, unknown>, null>;
export declare const geo_point_schema: import("superstruct").Struct<{
    latitude: number;
    longitude: number;
}, {
    latitude: import("superstruct").Struct<number, null>;
    longitude: import("superstruct").Struct<number, null>;
}>;
/**
 * Custom superstruct type.
 * Defines a RFC3339 timestamp string.
 */
export declare const timestamp_schema: import("superstruct").Struct<string, null>;
