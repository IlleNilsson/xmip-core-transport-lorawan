# xmip-core-transport-lorawan

LoRaWAN transport: a node is the network server its gateways point at over Semtech's UDP packet forwarder protocol, version 2; the MAC frame both ways, confirmed or not, its FRMPayload under AES-128 and CMAC MIC, a long Stream in fragments; a packet forwarder and a device of its own stand in for gateway and radio. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## A gateway points at a node

A LoRa gateway forwards what it hears to one network server, and a node is
that server. A Location's address is where the node listens for its
gateways, `lorawan://0.0.0.0:1700`; an address with no port listens on
1700, the port The Things Stack lists for the Semtech packet forwarder and
ChirpStack's gateway bridge listens on, so a gateway set up for either is
pointed at a node by its `server_address` alone. Semtech's packet forwarder
ships `serv_port_up` and `serv_port_down` at 1680, and sx1302_hal's at 1730:
whichever, both name the Location's port.

The protocol is the one Semtech's packet forwarder speaks, version 2:
`PROTOCOL.TXT` in
[Lora-net/packet_forwarder](https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT),
revision 1.4, version 2 since revision 1.3 added `TX_ACK`, and `PROTOCOL.md`
in
[Lora-net/sx1302_hal](https://github.com/Lora-net/sx1302_hal/blob/master/packet_forwarder/PROTOCOL.md),
revision 1.6, the same version; each read on 2026-11-27. The
packet_forwarder repository says the SX1302 and SX1303 concentrators take
sx1302_hal's forwarder instead. LoRa Basics Station, Semtech's newer
forwarder, speaks another protocol, over WebSocket, which is not built.

| Datagram | From | What the node does |
| --- | --- | --- |
| `PUSH_DATA` (0x00) | gateway | answers `PUSH_ACK` (0x01) at once, and keeps each `rxpk` whose CRC is good for the device its frame names |
| `PULL_DATA` (0x02) | gateway | answers `PULL_ACK` (0x04); where it came from is the way down to that gateway |
| `PULL_RESP` (0x03) | node | a `txpk` the gateway is to send, which it answers `TX_ACK` (0x05); a send it refused, `TOO_LATE` and the rest, fails naming why |

`datagram.rs` reads and writes the six, and `packet.rs` the `rxpk`, `txpk`
and `txpk_ack` JSON they carry, the PHY payload in base 64; both ends are
written once there. The Locations of a node naming one address share its one
socket, and a Receive and a Send Location of one device its session, its
counters and its fragments (`gateways.rs`, `server.rs`, through
`transport::sharing`). A gateway that asks for downlinks from a new address,
a packet forwarder started again, is sent again what it had not answered,
the new way.

**A Receive Location** takes what one device sends up, whole; its socket is
bound as the node starts. The origin names the gateway that heard the device
last and the device: `lorawan://aa555a0000000000/26011b2c?port=1&fcnt=0`.
The same frame heard by a second gateway is taken once. **A Send Location**
sends a Stream down at once, through the gateway that heard the device last,
on its `frequency` at its `data_rate` — EU868's second receive window,
869.525 MHz at SF12BW125, unless it says — where a Class C device listens
between its uplinks. A Send Location alone binds the socket as it first
sends, and waits for the gateway's next `PULL_DATA`, within its
`keepalive_interval`, 10 s as Semtech ships it. A Class A device, which
listens only just after its own uplink, is not reached yet (open problem
219).

The device's session is activated by personalization: its address is the
`dev_addr` setting, and its keys are the secret its Location names, a
`password` secret holding 64 hexadecimal digits, the network session key's
32 and then the application session key's, as a network server shows them,
read as each Stream is sent and as each receive opens its first frame.
Joining over the air is not built.

A frame a real device sends is opened whole: a frame with no FRMPayload
carries no port, its frame options, MAC commands, are skipped under the MIC
that covers them, and a payload on port 0 is under the network session key.
This crate answers no MAC command.

## The far end

A device behind a gateway (`device.rs`): the gateway is this crate's own
packet forwarder (`forwarder.rs`), which forwards each frame its device
sends in a `PUSH_DATA`, asks for downlinks each keepalive and hands each
`PULL_RESP` to the device at once, answered `TX_ACK`, whatever moment its
`tmst` names; the device is written with the frame, the keys and the
fragments the node's side is written with. `LorawanTransport::loopback()`
stands both ends on this machine over UDP, and the estate's service test
points one at a node in a process of its own
(`.src/test/service/far_ends/gateway.rs`).

AES-128 and its CMAC are RustCrypto's `aes` and `cmac` crates, constant-time,
the `aes` the estate's SFTP and Kerberos take too; a frame's MIC is checked in
constant time.

## Acknowledgement

A confirmed frame up is answered in the device's first receive window: a
frame with the ACK bit, through the gateway that heard it, timed one second
after it ended on that gateway's clock (`RECEIVE_DELAY1`), on its channel and
at its data rate. The window does not wait for the receive cycle to end, so
acceptance of an uplink is at-most-once.

A confirmed Stream down is one whose last frame is confirmed, and its Send
Location waits for the device's acknowledgement in its next frame up; what
that frame carries is kept for a receive. On the device's side, a confirmed
frame down is acknowledged after the whole receive cycle: on Accepted the
device's next frame up carries its ACK bit; on Failed it does not, and the
network server sends the frame again. LoRaWAN has no negative
acknowledgement, the ACK bit is the only answer (LoRaWAN L2 1.0.4, section
4.3.1.2), so nothing tells a network server not to send again: on Refused
the ACK bit rides up too, the frame taken and not sent again, and the
refusal is what the runtime audited. An unconfirmed frame down asks for no
ACK, so acceptance is at-most-once there. The ACK rides on the next frame up
the device sends, as LoRaWAN has it: no frame is sent up only to carry it.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `dev_addr`, `confirmed`, `frequency`, `data_rate` and `timeout`, and `SCHEMES`, `lorawan`. The wait `timeout` defaults to, `DEFAULT_TIMEOUT`, and the port an address that names none listens on, `PORT`, are there too, and the code reads them from there. It is the same wherever it is built, a box with no gateway in reach included. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — AES-128 and its CMAC, the codec, the network library and serde among them — are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check a `LoRaWAN` Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
