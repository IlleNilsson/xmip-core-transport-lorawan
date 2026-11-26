# xmip-core-transport-lorawan

LoRaWAN transport: the MAC frame — confirmed and unconfirmed data up and down, the frame counter, the FRMPayload under AES-128 and the CMAC MIC — a Stream longer than one frame travels as fragments on its own port; a loopback radio and network server stand in for the gateway. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

AES-128 and its CMAC are RustCrypto's `aes` and `cmac` crates, constant-time,
the `aes` the estate's SFTP and Kerberos take too; a frame's MIC is checked in
constant time.

## Acknowledgement

A confirmed frame down is acknowledged after the whole receive cycle: on
Accepted the device's next frame up carries its ACK bit; on Failed it does
not, and the network server sends the frame again. LoRaWAN has no negative
acknowledgement, the ACK bit is the only answer (LoRaWAN L2 1.0.4, section
4.3.1.2), so nothing tells a network server not to send again: on Refused the
ACK bit rides up too, the frame taken and not sent again, and the refusal is
what the runtime audited. An unconfirmed frame down
asks for no ACK, so acceptance is at-most-once there. Each Stream arrives
whole. The ACK rides on the next frame up the device sends, as LoRaWAN has it:
no frame is sent up only to carry it.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `dev_addr`, `confirmed` and `timeout`, and `SCHEMES`, `lorawan`. The wait `timeout` defaults to, `DEFAULT_TIMEOUT`, is there too, and the code reads it from there. It is the same wherever it is built, a box with no concentrator included. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — AES-128 and its CMAC among them — are behind the default feature. So the library the surfaces load can carry it without the code, for the language server and the desktop to suggest and check a `LoRaWAN` Location's settings though no node in their process loaded the technology, once the gathering crate of open problem 48 links it. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
