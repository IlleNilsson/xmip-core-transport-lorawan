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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
