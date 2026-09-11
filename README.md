# xmip-core-transport-lorawan

LoRaWAN transport: the MAC frame — confirmed and unconfirmed data up and down, the frame counter, the FRMPayload under AES-128 and the CMAC MIC — a Stream longer than one frame travels as fragments on its own port; a loopback radio and network server stand in for the gateway. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
