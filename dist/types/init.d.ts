import type * as Firestore from './types';
/**
 * Inits a Firestore instance by creating a [custom token](https://firebase.google.com/docs/auth/admin/create-custom-tokens).
 *
 * @param params
 * @returns A {@link Firestore.DB} object.
 */
export declare const init: ({ client_email, private_key, private_key_id, uid, project_id, claims, }: {
    project_id: string;
    private_key_id: string;
    client_email: string;
    private_key: string;
    uid: string;
    claims?: Record<string, string> | undefined;
}) => Promise<Firestore.DB>;
