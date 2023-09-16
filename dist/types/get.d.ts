import type * as Firestore from './types';
/**
 * Gets a single document from Firestore.
 * Reference: {@link https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/get}
 *
 * @param firestore The DB instance.
 * @param document_path The document path.
 */
export declare const get: <Fields extends Record<string, any>>({ jwt, project_id }: Firestore.DB, ...args: string[]) => Promise<Firestore.CustomDocument<Fields>>;
