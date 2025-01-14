export const FIRESTORE_ENDPOINT = 'https://firestore.googleapis.com';

/**
 * @returns The firestore endpoint for a project ID.
 * @param project_id
 * @param paths
 * @param suffix
 */
export const get_firestore_endpoint = (
  project_id: string,
  paths: string[] = [],
  suffix = ''
): URL => {
  const path = paths.join('/') + suffix;
  const endpoint = new URL(
    path,
    `${FIRESTORE_ENDPOINT}/v1/projects/${project_id}/databases/(default)/documents`
  );

  return endpoint;
};
