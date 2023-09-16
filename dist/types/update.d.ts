import type * as Firestore from './types';
/**
 * Updates a document.
 * Reference: {@link https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/patch}
 *
 * @param firestore
 * @param document_path
 * @param fields
 */
export declare const update: <Fields extends Record<string, any>>({ jwt, project_id }: Firestore.DB, ...args: [...string[], Fields]) => Promise<Firestore.CustomDocument<Fields>>;
