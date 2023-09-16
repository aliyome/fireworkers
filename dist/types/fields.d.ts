import type * as Firestore from './types';
/**
 * Types
 */
export type PrimitiveValues = Omit<Firestore.Value, 'mapValue' | 'arrayValue'>;
export type PrimitiveMappedValue = PrimitiveValues[keyof PrimitiveValues];
export type ArrayMappedValue = Array<PrimitiveMappedValue | ArrayMappedValue | MapMappedValue>;
export interface MapMappedValue {
    [key: string]: PrimitiveMappedValue | MapMappedValue | ArrayMappedValue;
}
export type MappedValue = PrimitiveMappedValue | ArrayMappedValue | MapMappedValue;
/**
 * Creates a document from an object of fields.
 * @param fields
 */
export declare const create_document_from_fields: (fields: Record<string, unknown>) => Firestore.Document;
/**
 * Maps all values to remove Firestore's metadata.
 * @param document The document to map.
 * @returns
 */
export declare const extract_fields_from_document: <DocumentFields extends Record<string, unknown>>(document: Firestore.Document) => Firestore.CustomDocument<DocumentFields>;
