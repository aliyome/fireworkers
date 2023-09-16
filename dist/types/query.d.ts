import type * as Firestore from './types';
/**
 * Performs a query to Firestore.
 * Reference: {@link https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/runQuery}
 *
 * @param firestore The DB instance.
 * @param query A [StructuredQuery](https://firebase.google.com/docs/firestore/reference/rest/v1/StructuredQuery) object.
 */
export declare const query: <Fields extends Record<string, any>>({ jwt, project_id }: Firestore.DB, query: Firestore.StructuredQuery, ...args: string[]) => Promise<Firestore.CustomDocument<Fields>[]>;
