import axios from 'axios';
import { Buffer } from 'buffer';

function buildNexusArtifactDownloadUrl(
  group: string,
  artifact: string,
  version: string,
): string {
  const slashedGroup = group.replace(/\./g, '/');
  return `http://localhost:8081/repository/maven-central/${slashedGroup}/${artifact}/${version}/${artifact}-${version}.jar`;
}

let nexusAuth = '';

beforeAll(() => {
  expect(process.env.NEXUS_PASS).not.toBeUndefined();
  nexusAuth = Buffer.from(`admin:${process.env.NEXUS_PASS}`, 'utf8').toString(
    'base64',
  );
});

it('can download a non-vulnerable package', async () => {
  const url = buildNexusArtifactDownloadUrl(
    'org.apache.commons',
    'commons-lang3',
    '3.12.0',
  );

  const res = await axios.get(url, {
    headers: {
      Authorization: `Basic ${nexusAuth}`,
      Host: 'localhost',
    },
  });

  expect(res.status).toBe(200);
});

it.only('throws when trying to download a vulnerable package', async () => {
  const url = buildNexusArtifactDownloadUrl(
    'com.fasterxml.jackson.core',
    'jackson-databind',
    '2.6.5',
  );

  let capturedErr;
  let res;

  try {
    res = await axios.get(url, {
      headers: {
        Authorization: `Basic ${nexusAuth}`,
      },
    });
  } catch (err) {
    capturedErr = err;
  }

  console.log('****', 'res ****\n', JSON.stringify(res, null, 2), '\n');
  console.log('****', 'capturedErr ****\n', JSON.stringify(capturedErr, null, 2), '\n');
  expect(capturedErr.response.status).toEqual(500);
});
