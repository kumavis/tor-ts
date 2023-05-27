import * as fs from 'node:fs';
import * as child_process from 'node:child_process';

export type Profile = {
  routerConfig: {
    OR_name: string,
    OR_ip: string,
    OR_port: number,
    OR_contact: string,
    version: string
  }
}

const pathForProfileName = function (profileName: string): string {
	return `${__dirname}/../profiles/${profileName}/`;
};

export const loadProfile = function (profileName: string): Profile {
	const pathd = pathForProfileName(profileName);
	const profile = JSON.parse(fs.readFileSync(`${pathd}profile.json`, 'utf8')) as Profile;
	return profile;
}

export type KeyInfo = {
  privid: Buffer,
  pubid: Buffer,
  pubkey: Buffer,
  privkey: Buffer
}

export const loadKeyInfo = function (profileName: string): { keyInfo: KeyInfo } {
	const pathd = pathForProfileName(profileName);
	const privkey = fs.readFileSync(`${pathd}priv-key.pem`);
	const privid = fs.readFileSync(`${pathd}priv-id-key.pem`);
	const pubid = fs.readFileSync(`${pathd}pub-id-key-rsa.pem`);
	const pubkey = fs.readFileSync(`${pathd}pub-key-rsa.pem`);
	const keyInfo = { privid, pubid, pubkey, privkey }
	return { keyInfo }
}

//create onion and id keys in OR_name directory if they don't exist
export const createProfile = function (routerConfig: Profile['routerConfig']) {
  const { OR_name } = routerConfig;
  const pathd = pathForProfileName(OR_name);
  fs.mkdirSync(pathd, { recursive: true });
  let privkey;
  try {
    privkey = fs.readFileSync(`${pathd}priv-key.pem`);
  } catch (e) {
    child_process.execSync(`openssl genrsa -out ${pathd}priv-key.pem 1024`);
    child_process.execSync(`openssl rsa -in ${pathd}priv-key.pem -pubout > ${pathd}pub-key.pem`);
    child_process.execSync(`openssl rsa -in ${pathd}priv-key.pem -out ${pathd}pub-key-rsa.pem -outform PEM -RSAPublicKey_out`);
    privkey = fs.readFileSync(`${pathd}priv-key.pem`);
  };

  let privid
  try {
    privid = fs.readFileSync(`${pathd}priv-id-key.pem`);
  } catch (err) {
    child_process.execSync(`openssl genrsa -out ${pathd}priv-id-key.pem 1024`);
    child_process.execSync(`openssl rsa -in ${pathd}priv-id-key.pem -pubout > ${pathd}pub-id-key.pem`);
    child_process.execSync(`openssl rsa -in ${pathd}priv-id-key.pem -out ${pathd}pub-id-key-rsa.pem -outform PEM -RSAPublicKey_out`);
    privid = fs.readFileSync(`${pathd}priv-id-key.pem`);
  }

  const profile = { routerConfig };
  fs.writeFileSync(pathd + 'profile.json', JSON.stringify(profile, null, 2));
};
