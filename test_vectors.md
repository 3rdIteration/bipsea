# BIP-85 Test Vectors

## Master Key

```
xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
```

All derivations use index `0` unless otherwise noted.

---

## BIP-39 Mnemonic

Application code: `39'`, language `0'` (English).

| Words | Path | Mnemonic |
|-------|------|----------|
| 12 | `m/83696968'/39'/0'/12'/0'` | `girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose` |
| 15 | `m/83696968'/39'/0'/15'/0'` | `aerobic able grant hobby uncle boss filter auction tip exact mixed again soda race absorb` |
| 18 | `m/83696968'/39'/0'/18'/0'` | `near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token` |
| 21 | `m/83696968'/39'/0'/21'/0'` | `feed excite donkey pepper enhance box stock asset submit tomorrow quick divert frost setup cream elder unable harbor enlist fabric this` |
| 24 | `m/83696968'/39'/0'/24'/0'` | `puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano` |

---

## XPRV

Application code: `32'`.

| Path | Derived Key |
|------|-------------|
| `m/83696968'/32'/0'` | `xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX` |

---

## WIF

Application code: `2'`.

| Path | Derived Key |
|------|-------------|
| `m/83696968'/2'/0'` | `Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp` |

---

## HEX

Application code: `128169'`.

| Bytes | Path | Output |
|-------|------|--------|
| 16 | `m/83696968'/128169'/16'/0'` | `3c678a761e24067fecc41c328a3d253d` |
| 20 | `m/83696968'/128169'/20'/0'` | `693b03234d53d833aa37cf5fd29eb24d9cb9a4f1` |
| 24 | `m/83696968'/128169'/24'/0'` | `7a5e93423bc0a5642c84646aa44728f70f5e99effe50730a` |
| 32 | `m/83696968'/128169'/32'/0'` | `ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc` |
| 64 | `m/83696968'/128169'/64'/0'` | `492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c` |

---

## Base64

Application code: `707764'`.

| Length | Path | Output |
|--------|------|--------|
| 20 | `m/83696968'/707764'/20'/0'` | `RrH7uVI0XlpddCbiuYV+` |
| 24 | `m/83696968'/707764'/24'/0'` | `vtV6sdNQTKpuefUMOHOKwUp1` |
| 43 | `m/83696968'/707764'/43'/0'` | `35+ooHABYZX3Aup7RrYMRrOTyqFzs5IaEdt/YTZZlPl` |
| 64 | `m/83696968'/707764'/64'/0'` | `dyff6cDYUIzIEJTQpxQQUPdiz0x2vggHq8QKm7AHuUX84Z5uZaHlHV40kYPgmePM` |
| 86 | `m/83696968'/707764'/86'/0'` | `CWjr5L/WrSdDTlCK4oOq01Gz6jCmx3feszswVa9Yg+TiecCLZk+DOiTJM/CnNcPFkHZka7suxM0D53RpP0eNRw` |

---

## Base85

Application code: `707785'`.

| Length | Path | Output |
|--------|------|--------|
| 10 | `m/83696968'/707785'/10'/0'` | `@;HdO2<rpP` |
| 12 | `m/83696968'/707785'/12'/0'` | `` _s`{TW89)i4` `` |
| 20 | `m/83696968'/707785'/20'/0'` | `xk0JcN3MW<VDMWR6R#bT` |
| 32 | `m/83696968'/707785'/32'/0'` | `` YnpDp47WRKy`XEThxBgX_I)^dqcW`+8P `` |
| 64 | `m/83696968'/707785'/64'/0'` | `` F``p};+AhBuXP%6oHacLEoPSO5h=fX7MA=q@hEa=&7AoA$O{pPHP)c9C+QU&<sM; `` |
| 80 | `m/83696968'/707785'/80'/0'` | `k^@w(83#3OSs+62bP*XZ` `` `MlP7>sG_Gp19h(e@*9s#CEYCmY>doQ{d@B8o}u#Q2Q#z2#$7^fFrCH&toB6 `` |

---

## Dice

Application code: `89101'`.

| Sides | Rolls | Path | Output |
|-------|-------|------|--------|
| 6 | 1 | `m/83696968'/89101'/6'/1'/0'` | `3` |
| 6 | 10 | `m/83696968'/89101'/6'/10'/0'` | `1,0,0,2,0,1,5,5,2,4` |
| 6 | 50 | `m/83696968'/89101'/6'/50'/0'` | `0,4,3,3,2,4,0,2,1,3,5,1,0,2,3,0,5,3,2,2,0,4,4,1,3,5,0,0,3,2,3,4,0,5,4,0,5,3,1,2,4,3,4,3,2,0,2,4,2,0` |
| 10 | 1 | `m/83696968'/89101'/10'/1'/0'` | `6` |
| 10 | 10 | `m/83696968'/89101'/10'/10'/0'` | `4,6,4,9,2,7,3,9,4,1` |
| 10 | 50 | `m/83696968'/89101'/10'/50'/0'` | `2,2,6,5,6,9,9,0,4,1,4,0,2,5,2,8,9,6,7,6,6,0,9,6,2,9,8,0,4,4,3,8,2,8,5,9,0,3,6,2,4,7,9,3,9,7,9,1,9,5` |
| 20 | 1 | `m/83696968'/89101'/20'/1'/0'` | `18` |
| 20 | 10 | `m/83696968'/89101'/20'/10'/0'` | `18,09,12,11,01,00,04,08,12,15` |
| 20 | 50 | `m/83696968'/89101'/20'/50'/0'` | `17,01,17,17,12,07,19,03,19,09,19,00,10,11,12,00,08,15,14,15,11,18,06,00,17,11,07,13,06,15,17,10,07,09,08,14,10,00,11,04,16,07,17,16,01,03,08,00,07,14` |

---

## DRNG

Application code: `0'`.

| Bytes | Path | Output |
|-------|------|--------|
| 32 | `m/83696968'/0'/32'/0'` | `dddff9cfe0a9123003dd6ffde10e075c88c1b62d1c1e804a0025ee83daae9fee` |
| 64 | `m/83696968'/0'/64'/0'` | `dddff9cfe0a9123003dd6ffde10e075c88c1b62d1c1e804a0025ee83daae9fee50923bd2f2cc6f51f1a3fc4bad72fe89ec13a59e6eea3e97d6281d65fa614766` |

---

## GPG (OpenPGP)

Application code: `828365'`.

### Key Type 0 — RSA

| Key Bits | Path | Entropy (hex) |
|----------|------|---------------|
| 1024 | `m/83696968'/828365'/0'/1024'/0'` | `2b9380df43421f46b5c38e13ea80612ff53488bc5d272e86d493ee1eecf738bb7b50e4978b7352f95772f1211483b0e6bba86c544a946b10d76ed493b8c2e01f` |
| 2048 | `m/83696968'/828365'/0'/2048'/0'` | `98c4fb6d76f203e8828bdfd28416edca7a83a9b203901f7ad31f056cda8b3c25b19e5fd2aa642ca0abb9ed8bebf3d141af6c76b28a19eba624bdc6f8a76ce138` |
| 4096 | `m/83696968'/828365'/0'/4096'/0'` | `2d2ef3335dc51e7a0642bfe86fba0bb4e8401b703d8d679bb1a31d75f8a81f1fd52b20b2eae50ef6e0378b8755f4f0426c68b54f11edc0c848e017e81bb2ad87` |

### Key Type 1 — ECDSA (NIST P-256)

| Key Bits | Path | Entropy (hex) |
|----------|------|---------------|
| 256 | `m/83696968'/828365'/1'/256'/0'` | `0e90b553528cd97a033c282f54cf72c1020adaec205d5c0e57e9f2556d06fea683618e4be8f91e7e059647f9d6373eb8b5f535e7ba4097cfb3e93c4957843614` |

### Key Type 2 — EdDSA

| Key Bits | Path | Entropy (hex) |
|----------|------|---------------|
| 256 | `m/83696968'/828365'/2'/256'/0'` | `f3bb8b3d6b81fbd202c34b59ce7e97c83969e9b5733b936de16c51119c7a48239ddf66729ef5e4df97ea39471f05a89f070869b3f9d72d69f3ae8bd7ee4fb6b3` |

### Key Type 3 — ECDSA (NIST P-384, P-521)

| Key Bits | Path | Entropy (hex) |
|----------|------|---------------|
| 256 | `m/83696968'/828365'/3'/256'/0'` | `f52586f58521916b9f28b0058be86effcde82e571eabada9e3f63c6f67752ff12a4d3bf2fffe0f147164945691605a58f28f6bded869c38b3db9f0e577d83728` |
| 384 | `m/83696968'/828365'/3'/384'/0'` | `830005ea400f7a03c27aa06a9728fe311c9a48dc31bd417f07b96c69edc73d25baa00d04b9dbbe6f42539b06d9ef1ba62ed73d4a3a992302aae09e17e0d9f42f` |
| 521 | `m/83696968'/828365'/3'/521'/0'` | `3524b3cbe60eb78a156dae44674702f69381afe5292d6d15d7801b7e530f2a0616b7b876c0ba85d6e675587fdc0ce2242ad00252493ec9c3a024217d1e2aa954` |

### Key Type 4 — EdDSA (Curve25519)

| Key Bits | Path | Entropy (hex) |
|----------|------|---------------|
| 256 | `m/83696968'/828365'/4'/256'/0'` | `97ee4490d89bf257e9a038e2af12824fba47fec721970ca1fc1c094650d2716d75491402530776ba31d215fac6c2de0cb6661f1d380b682e20246bf962cdf385` |
| 384 | `m/83696968'/828365'/4'/384'/0'` | `3fa833db4195fbd7a9c4e3f6fdb65ffb8951c5c65ca0cce441a4410e11aa96fcb094ed8c1fb5317448ae098ca9cae2c351b513e47d1b74e4c80c1facdf7b0a5a` |
| 512 | `m/83696968'/828365'/4'/512'/0'` | `985f0131503109fc7fb2ab15e6a86846888e4b9a9f4f11f0d7b30dba4570cf8cc728a4c8ce9bbeb9b9819fbe924bb2d6d71a9c8332635cfb5db5008364f3a43a` |
