import * as fs from 'fs';

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
	return __dirname+'/../profiles/'+profileName+'/';
};

export const loadProfile = function (profileName: string): Profile {
	const pathd = pathForProfileName(profileName);
	const profile = JSON.parse(fs.readFileSync(pathd+'profile.json', 'utf8')) as Profile;
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
	const privkey = fs.readFileSync(pathd+'priv-key.pem');
	const privid = fs.readFileSync(pathd+'priv-id-key.pem');
	const pubid = fs.readFileSync(pathd+'pub-id-key-rsa.pem');
	const pubkey = fs.readFileSync(pathd+'pub-key-rsa.pem');
	const keyInfo = { privid, pubid, pubkey, privkey }
	return { keyInfo }
}
