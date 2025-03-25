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

it('throws when trying to download a vulnerable package', async () => {
  const url = buildNexusArtifactDownloadUrl(
    'com.fasterxml.jackson.core',
    'jackson-databind',
    '2.6.5',
  );

  await expect(async () => {
    await axios.get(url, {
      headers: {
        Authorization: `Basic ${nexusAuth}`,
      },
    });
  }).rejects.toThrow('Request failed with status code 500');
});
