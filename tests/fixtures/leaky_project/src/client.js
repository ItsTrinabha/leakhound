// DELIBERATELY LEAKY TEST FIXTURE - values are fake.
const firebaseConfig = { apiKey: "{{GOOGLE_API_KEY}}", projectId: "acme-prod" };
const authHeader = `Bearer {{JWT}}`;

export function headers() {
  return { Authorization: authHeader, "X-Client": firebaseConfig.projectId };
}
