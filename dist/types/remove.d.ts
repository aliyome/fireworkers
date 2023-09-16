import type * as Firestore from './types';
/**
 * Removes a document from Firestore.
 * Reference: {@link https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/delete}
 *
 * @param firestore The DB instance.
 * @param document_path The document path.
 *
 * @returns `true` if the deletion was successful.
 */
export declare const remove: ({ jwt, project_id }: Firestore.DB, ...args: string[]) => Promise<boolean>;
