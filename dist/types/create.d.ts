import type * as Firestore from './types';
/**
 * Gets a single document from Firestore.
 * Reference: {@link https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/createDocument}
 *
 * @param firestore
 * @param collection_path
 * @param fields
 */
export declare const create: <Fields extends Record<string, any>>({ jwt, project_id }: Firestore.DB, ...args: [...string[], Fields]) => Promise<Firestore.CustomDocument<Fields>>;
