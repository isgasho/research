# End-to-end (e2ee) encrypted apps ecosystem overview

author: [Sylvain Kerkour](https://kerkour.fr)

Prepared for: [Bloom](https://bloom.sh)

------------------------------

This research document details how work the existing end-to-end encrypted (e2ee) apps with words intelligible
for mere mortals. This is not by any mean an exhaustive list but it's pretty representative of the state of the market.

Please [open an issue](https://gitlab.com/bloom42/research/e2ee_apps/-/issues) if you think something is wrong.


## Table of contents


* [Signal 👍](#signal)
* [Proton 😐 / 👎](#proton)
* [1Password 👍](#1password)
* [Matrix 👍 / 😐](#matrix)
* [Wire](#wire)
* [Bitwarden 👍](#bitwarden)
* [Bear 👍](#bear)
* [NordPass](#nordpass)
* [Joplin](#joplin)
* [NextCloud](#nextcloud)
* [Standard note](#standard-note)
* [Day one](#day-one)
* [Omnifocus](#omnifocus)
* [Turtl](#turtl)
* [Gopass](#gopass)
* [Firefox Sync 👍](#firefox-sync)
* [WhatsApp](#whatsapp)
* [LastPass](#lastpass)
* [Scuttlebutt 😐 / 👎](#scuttlebutt)
* [Others](#others)

------------------------------


## Signal

rating: 👍

When we ask for secure messaging, the internet answer: Signal. This is THE reference crypto app
and is recommended by a lot of famous people working in the infosec field.


### Resources
* https://medium.com/mercuryprotocol/introducing-signal-protocol-to-dust-19b66c9331be
* http://engineering.mindlinksoft.com/end-to-end-encryption-with-the-signal-protocol/
* https://medium.com/@justinomora/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4
* https://signal.org/blog/asynchronous-security/
* https://signal.org/blog/advanced-ratcheting/
* https://devpoga.org/post/2019-09-04_notes_on_the_signal_protocol/
* https://signal.org/docs/specifications/xeddsa
* https://signal.org/docs/specifications/x3dh/
* https://blog.cloudboost.io/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-3e31830c456f
* https://taravancil.com/blog/axolotl-an-attempt-at-a-summary/

## Proton

rating: 😐 / 👎

Another famous e2ee service. Unfortunately after further investigation I can't longer recommend this service. They provide working encryption but the metadata are not encrypted, and everything around cryptography seems weak.

### Authentication

They Secure Remote Password (SRP) v6a in order to not transmit the user's password to the server.


### Emails

Use PGP, with protonmail as the key exchange server


The private key is symmetrically encrypted with the mailbox password using AES-256. The public key and encrypted private key are then stored on the ProtonMail server along with the user’s other account information and retrieved whenever a user logs in successfully.


The encrypted private key is decrypted on successful mailbox password entry on the user’s local device and can be used to read and sign messages during that session.

### Calendar

Any action you take, like creating, editing, or deleting an event, will be digitally signed using a primary address key that is linked to the ProtonMail address you used to join the calendar.

For every calendar, we will generate a calendar key (for those interested, it will be an ECC Curve25519 PGP key)
This calendar key will be used to encrypt the event data.
This calendar key will then be symmetrically encrypted (PGP standard) using a 32-byte passphrase that is randomly generated on your device. Once it is encrypted, your calendar key will be stored on the ProtonCalendar backend server.
Each member of a calendar will have a copy of the same passphrase that is encrypted and signed using their primary address key.
The signature ensures that no one, not our server or any third-party adversary, changed the passphrase.


To invite a new member to your calendar, you need to grant them access to the calendar private key and make sure that they can decrypt it.
If you invite a new member, ProtonCalendar first has to fetch the invited member’s public key that is linked to their email address. Your ProtonCalendar client will then encrypt the calendar’s passphrase on your device using the invited member’s public key. The passphrase is then signed using your email address key.
The invited member, if they decide to join the calendar, can decrypt the passphrase using their address key. They can also verify that the signature on the passphrase belongs to your email address key. This lets the invited member cryptographically verify that you invited them. To accept the invitation, ProtonCalendar will then pin the passphrase for the invited member by replacing your signature with one created using their own email address key. This signature will later be used by the invited member to verify the passphrase at each application start.

All event data can also be split into two categories:

    Encrypted and signed properties
    Signed-only properties

Our server needs to be able to access some properties of an event so that it can retrieve and index the events efficiently. The properties that our server must access are the signed-only properties, which include:

    The start/end time of an event, along with its time zone information
    The repetition rule and the date/time exclusions
    The unique event identifier
    Time information for alarms

All the remaining properties will be encrypted and signed on your device before they are stored on our servers. In other words, all of an event’s critical information, like the title, description, location, and attendees, will be stored securely and privately with end-to-end encryption.

ils ont un mailbox password (user_passphrase) qui encrypte les (publickKey, secretKey) pairs

calendrier: Ils chiffrent les cles individuelles avec les cles publiques pour eviter la forge / le
swapping

calendar event location

### Resources

* https://protonmail.com/blog/elliptic-curve-cryptography/
* https://protonmail.com/blog/zero-access-encryption/
* https://protonmail.com/blog/what-is-pgp-encryption/
* https://protonmail.com/blog/what-is-end-to-end-encryption/
* https://protonmail.com/blog/encrypted_email_authentication/
* https://protonmail.com/security-details
* https://protonmail.com/support/knowledge-base/single-password/
* https://protonmail.com/blog/protoncalendar-security-model/
* https://protonmail.com/blog/thunderbird-outlook-encrypted-email/
* https://protonmail.com/blog/proton-bridge-linux-launch/
* https://protonmail.com/blog/bridge-security-model/



## 1Password

If you have access to a vault, a copy of the vault key is encrypted with your public key. Only you, the holder of your private key, are able to decrypt that copy of the vault key. Your priv-_ate key is encrypted with a key encryption key (􏰄􏰍􏰄) that is derived from your Master Password and Secret Key.


### Resources

* https://support.1password.com/emergency-kit/
* https://support.1password.com/secret-key/



# Matrix

The cryptography is strong (albeit very old and thus the implementations can fail). Unfortunately, they leak a lot of metadata.

* https://blog.jabberhead.tk/2019/03/10/a-look-at-matrix-orgs-olm-megolm-encryption-protocol/
* https://matrix.org/docs/guides/end-to-end-encryption-implementation-guide
* https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md
* https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md



## Wire

* https://medium.com/@wireapp



# Bitwarden

* https://fossil.birl.ca/bitwarden-cli/doc/trunk/docs/build/html/crypto.html
* https://github.com/jcs/rubywarden/blob/master/API.md
* https://help.bitwarden.com/article/change-your-master-password/

* `master key` is derived from user's password.
* `encryption Key` & `macKey` are encrypted with the `master key` (and sent encrypted to the server and differents devices).



### BWN-01-007 – Weak master passwords are allowed
A user’s master password derives the master encryption key which is used to unlock all other data in a user’s Bitwarden vault. Bitwarden allows users to choose any master password. The only restriction in place for a master password that it must be at least 8 characters in length. Due to this lax policy, users can still choose very weak passwords such as “12345678” and “iloveyou”.

#### Impact
Users that choose weak passwords can suffer from a compromised vault. If a malicious actor were to gain access to Bitwarden’s database or the user’s device, offline brute force attacks on these weak master passwords would be trivial. Although Bitwarden already employs defenses for online brute force attacks, a master password that is re-used elsewhere or is easily guessable could also lead to a compromised vault.

#### Resolution
Password strength checks and warnings have been implemented in Bitwarden client applications to encourage users to use stronger master passwords during account registration and during master password changes. zxcvbn was chosen as the library to aid in determining the overall strength of the master password.


### BWN-01-010 – Changing the master password does not change encryption keys

Multiple keys are involved with a user’s Bitwarden account:
1. A “public key” and “private key” is used for the purposes of sharing protected information with other Bitwarden users (via organizations).
2. An “encryption key” and “mac key” is used to encrypt all data in a Bitwarden user’s vault. These keys also protect the user’s private key (from #1 above).
3. A “master key” is derived from a Bitwarden user’s master password. The master key is used to protect and unlock the encryption key and mac key (from #2 above).
During a password change operation, only the master key is changed which results in re-encrypting the encryption key and mac key. Since the encryption key and mac key do not change, no other data in the user’s vault is re-encrypted and decrypting existing and new data uses the same encryption key.

#### Impact

If a user’s encryption key is stolen by an attacker via malware on the user’s device or other means, changing the master password will not change that attacker’s ability to decrypt any new data created under the user’s account since the same key is still being used.
Since remote access to encrypted vault data requires authenticating with a master password (which can be changed), maliciously gaining access to any new data under a user’s Bitwarden account would require that the user still have a compromised device. Therefore, even if the encryption key and mac key were rotated on a master password change, it should be assumed that the same attacker could also obtain the new encryption key and thus still decrypt old and new vault data from that user’s account.

#### Resolution

An option to rotate the encryption key and mac key has been added to the change password operation. Rotating the keys will generate new, random key values and re-encrypt all vault data with these new keys.




## Bear

rating: 👍

ils ont `app_encryption_key` derivee de `user_passphrase` qui encrypte les `note_encryption_key`

`user_passphrase` est encryptee avec une cle random par device, et stockee dans la keychain


Caching encryption keys in the app memory makes them potentially accessible to attackers. That’s why the app has a “lock” button to manually lock the notes and invalidate caches. After a certain amount of time, it locks them automatically (locking also happens after user quits or removes the app from memory).
Defining the correct time interval is crucial for the balance between security and usability: the more keys are stored in memory, the easier it is to locate them. At the same time, we shouldn’t distract users too often.

Using monotonic clock.  It counts seconds after a device reboot so it is not affected by time zones and manual time change.

Bear app users can control the locking interval, which introduces a risk that an attacker will change the interval to have more time for reversing. So, instead of saving auto-lock settings in UserDefaults, the app saves them in the local Keychain and protects by biometrics (repeat after us — this is called “defense in depth approach”, not “paranoia”).


Imagine that vulnerability or bug is discovered in the encryption library or in the app — we’d need to update the application and to migrate the users to a new cryptographic core really quickly.
That’s why each SFPassword object has a reference to a particular encryption version and the app checks the encryption version before trying to encrypt/decrypt the data.

### Resources

* https://www.cossacklabs.com/blog/end-to-end-encryption-in-bear-app.html
* https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme










## NordPass

### Resources

https://nordpass.com/blog/how-does-password-manager-work/


## Joplin

### Resources

* https://joplinapp.org/spec/



## NextCloud

### Resources

* https://nextcloud.com/endtoend/




## Standard note

### Resources

* https://blog.standardnotes.org/encrypted-ephemeral-customer-service/
* https://blog.standardnotes.org/end-to-end-encrypted-collaboration/



# Day one

journaling app

### Resources

* https://medium.com/day-one/end-to-end-encryption-for-day-one-sync-af4ba31fb36e


items are individually encrypted using symmetric `entry key`

Each entry or image key (“content key”) is secured by an asymmetric journal key pair

Both the server and device can use the public journal key to create new content and encrypt its key.

Each journal has its own list of journal key pairs called the journal vault
The newest key in the vault is designated as the active key pair, which is used to encrypt and sign new entries. The rest are “retired” and used only for decrypting and verifying entries that were previously encrypted with that key pair.

-> pas de rotation

The vault for a journal is secured with a randomly generated symmetric vault key. This key encrypts and decrypts the private keys in the vault. It also encrypts and decrypts the journal name. When a new journal key is added, the vault key must also be changed. Each journal has its own independent vault and associated vault key.

The journal vault key is secured using an asymmetric account master key pair. Each user account has its own independent account master key, which is always generated on your device. Only the public key is transmitted and stored on the sync server with your user account. The private key remains on your device.

If the entry key was generated by the server, it is not trusted for use in future updates made on your device. Otherwise, an attacker with server access could use that key to read the updated content. We use cryptographic signatures to indicate which keys are trusted.

When you create an entry on your device, it generates a signature of the encrypted entry key using the private journal key. This signature is stored alongside the encrypted entry key. When verified, it proves that the entry key was generated by a device with access to the private journal key, and therefore can be trusted.
When a server-side process such as IFTTT creates an entry, it encrypts the entry key with the public journal key. But because it doesn’t have access to the journal private key, it cannot sign the encrypted entry key. The absence of a signature is a signal to your device that the entry key needs to be replaced with a new one, so that future updates to that entry can’t be read by the server.[7]


The encrypted journal vault key is signed with the account master private key, to allow verification that the key and the vault it encrypts are trusted. This prevents an attacker from secretly replacing a journal vault and key with their own



## Omnifocus

* https://discourse.omnigroup.com/t/omnifocus-sync-encryption-gory-technical-details/24611


`user passphrase` encrypt/decrypt a `key management file`

`When the user changes their passphrase, therefore, we don’t need to re-encrypt every file immediately. We can simply re-encrypt the metadata blob with the new passphrase.`


on leur a suggere d'utiliser un counter plutot que random for IVs

## Turtl

(notes)

* https://turtlapp.com/docs/security/encryption-specifics/

Encrypted objects have the ability to store their own key in their data, encrypted via another object’s key. Sounds confusing, so the primary example would be this: Note A has its own key that will decrypt its data. Note A is in Space B. Note A’s data contains Note A’s key encrypted with Space B’s key. So if Alice shares Space B with Bob, she can share Space B’s key, and now Bob has the ability to decrypt any note in Space B (including Note A).

This is what allows objects to be sharable in Turtl without compromising the master key…sharing can be done granularly and on a per-object basis. That said the only objects that are currently sharable in Turtl are spaces.





# Gopass

* https://github.com/gopasspw/gopass/blob/master/docs/security.md

use git repositories as 'vault' (per user / group)

use gpg for encryption




# Firefox Sync

* https://hacks.mozilla.org/2018/11/firefox-sync-privacy/
* https://blog.mozilla.org/warner/2014/05/23/the-new-sync-protocol/
* https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol
* https://docs.google.com/document/d/1IvQJFEBFz0PnL4uVlIvt8fBS_IPwSK-avK0BRIHucxQ/edit#heading=h.mqdsr2ucjm61 (*Scoped Encryption Keys for Firefox Accounts*)

from `user_password` are derived 2 keys: `authPW` and `unwrapBKey`. `authPW` is used as authentication
password for the server. `unwrapBKey`is used to encrypt a `keyB` wich is used to encrypt the data
and stored encrypted on the server.



## WhatsApp


The crypto seems string, but as it's neither open source nor from a trustworthy vender, we can't recommend it.

Public Key Types
• Identity Key Pair – A long-term Curve25519 key pair, generated at install time .
• Signed Pre Key – A medium-term Curve25519 key pair, generated at install time, signed by the Identity Key, and rotated on a periodic timed basis .

• One-Time Pre Keys – A queue of Curve25519 key pairs for one time use, generated at install time, and replenished as needed .
Session Key Types
• Root Key – A 32-byte value that is used to create Chain Keys .
• Chain Key – A 32-byte value that is used to create Message Keys .
• Message Key – An 80-byte value that is used to encrypt message contents. 32 bytes are used for an AES-256 key, 32 bytes for a HMAC-SHA256 key, and 16 bytes for an IV.

chaque membre d'une dicussion a `Chain Key` pour le ratchet



# LastPass

The Master Password = user's password

password -> PBKFD -> encryption key
                  -> another PBKFD -> authentication hash


LastPass uses RSA public key cryptography to allow users to share credentials with trusted parties synced through LastPass

When a Shared Folder is created, a 256-bit encryption key is generated and used to encrypt the data stored in the Shared Folder.

This encryption key is further encrypted with the public key of anyone invited to the Shared Folder and can be decrypted only with the invitee’s corresponding private key.

All users who share folders generate a 2048-bit RSA key pair locally on their own device. The user’s private key is encrypted with their vault encryption key using AES-256-bit encryption then sent to LastPass along with the user’s public key.
 The encrypted private key is sent to LastPass so that it can be attained from other devices in the future. Public keys will be used by other users to encrypt data that can only be decrypted with the original private key.


EncFS is used to encrypt system data needed to run the LastPass service. EncFS is a Filesystem in Userspace (FUSE)-based encrypted filesystem that automatically encrypts all files added to the volume.


# Scuttlebutt

Chaque user a une keypair ed25519. c'est son identite


* https://ssbc.github.io/scuttlebutt-protocol-guide
* http://scuttlebot.io/more/protocols/secure-scuttlebutt.html
* https://news.ycombinator.com/item?id=22909984 (Scuttlebot: Peer-to-peer database, identity provider, and messaging system)
* https://news.ycombinator.com/item?id=22915460 (What Is Scuttlebutt?)

## Others

These apps or libraries do not necessarly use e2ee but are still worth looking at because they extensively use cryptography.

### Dat

* https://datprotocol.github.io/how-dat-works/

### libsodium

* https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
* https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption
* https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
* https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes

* https://libsodium.gitbook.io/doc/secret-key_cryptography
* https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox
* https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
* https://libsodium.gitbook.io/doc/secret-key_cryptography/encrypted-messages



## Apple cryptoKit

* https://developer.apple.com/documentation/cryptokit




* https://github.com/sobolevn/awesome-cryptography
* https://github.com/tutao/tutanota
* https://blog.cryptographyengineering.com/2014/08/13/whats-matter-with-pgp/

